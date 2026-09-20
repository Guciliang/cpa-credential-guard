// Package profiles persists named proxy configurations separately from runtime
// ownership state. The raw proxy URL is stored only in this restrictive
// user-managed catalog; management responses expose the remark and redacted
// endpoint, never proxy userinfo.
package profiles

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/proxy"
)

const (
	fileName        = "proxy-profiles.json"
	maxFileBytes    = 1 << 20
	maxProfiles     = 256
	maxRemarkLength = 120
)

var (
	ErrNotFound       = errors.New("proxy profile not found")
	ErrInvalid        = errors.New("proxy profile is invalid")
	ErrReferenced     = errors.New("proxy profile is referenced by a fallback")
	ErrActiveFallback = errors.New("proxy profile has an active fallback")
	identifier        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$`)
)

type storedProfile struct {
	ID                  string    `json:"id"`
	Remark              string    `json:"remark"`
	ProxyURL            string    `json:"proxy_url"`
	FallbackMode        string    `json:"fallback_mode,omitempty"`
	FallbackProfileID   string    `json:"fallback_profile_id,omitempty"`
	FallbackActive      bool      `json:"fallback_active,omitempty"`
	FallbackAuthIndexes []string  `json:"fallback_auth_indexes,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type document struct {
	SchemaVersion int             `json:"schema_version"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Profiles      []storedProfile `json:"profiles"`
}

// Profile is an in-process profile. ProxyURL never crosses the management
// response boundary; callers should use Projection for UI/API data.
type Profile struct {
	ID                  string
	Remark              string
	ProxyURL            string
	FallbackMode        string
	FallbackProfileID   string
	FallbackAuthIndexes []string
	Projection          domain.ProxyProfileProjection
}

type LoadReport struct {
	Initialized      bool
	RecoveredCorrupt bool
	QuarantinedPath  string
	Incompatible     bool
	Error            string
}

// Store is a small atomic JSON catalog for user-created proxy profiles. It is
// intentionally separate from state.Store so runtime ownership state remains
// free of raw proxy URLs.
type Store struct {
	dir       string
	root      *os.Root
	now       func() time.Time
	mu        sync.RWMutex
	profiles  map[string]storedProfile
	lastError error
}

func New(dir string) (*Store, LoadReport, error) {
	return NewWithClock(dir, time.Now)
}

func NewWithClock(dir string, now func() time.Time) (*Store, LoadReport, error) {
	if now == nil {
		now = time.Now
	}
	if err := validateDir(dir); err != nil {
		return nil, LoadReport{Error: err.Error()}, err
	}
	if err := rejectSymlinkComponents(dir); err != nil {
		return nil, LoadReport{Error: err.Error()}, err
	}
	root, err := openProfileRoot(filepath.Clean(dir))
	if err != nil {
		return nil, LoadReport{Error: "profile directory cannot be opened safely"}, fmt.Errorf("open profile directory: %w", err)
	}
	store := &Store{dir: dir, root: root, now: now, profiles: map[string]storedProfile{}}
	if err := store.restrictDirectory(); err != nil {
		_ = root.Close()
		return nil, LoadReport{Error: err.Error()}, err
	}
	report, err := store.load()
	if err != nil {
		_ = root.Close()
		return nil, report, err
	}
	return store, report, nil
}

func validateDir(dir string) error {
	clean := filepath.Clean(strings.TrimSpace(dir))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.Dir(clean) == clean || strings.ContainsAny(dir, "\x00\r\n") {
		return errors.New("profile directory is unsafe")
	}
	return nil
}

// openProfileRoot pins the configured directory and creates missing
// components beneath that pinned anchor. It mirrors the state store boundary:
// a later path swap cannot redirect profile catalog I/O elsewhere.
func openProfileRoot(path string) (*os.Root, error) {
	clean := filepath.Clean(path)
	anchorPath := "."
	relative := clean
	if filepath.IsAbs(clean) {
		volume := filepath.VolumeName(clean)
		if volume == "" {
			anchorPath = string(filepath.Separator)
		} else {
			anchorPath = volume + string(filepath.Separator)
		}
		relative = strings.TrimPrefix(clean, anchorPath)
		relative = strings.TrimLeft(relative, string(filepath.Separator))
	}
	if relative == "" || relative == "." {
		return nil, errors.New("profile directory must not be a filesystem root")
	}
	anchor, err := os.OpenRoot(anchorPath)
	if err != nil {
		return nil, fmt.Errorf("open profile anchor: %w", err)
	}
	closeAnchor := true
	defer func() {
		if closeAnchor {
			_ = anchor.Close()
		}
	}()
	parts := strings.Split(relative, string(filepath.Separator))
	prefix := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			return nil, errors.New("profile directory escapes its anchor")
		}
		if prefix == "" {
			prefix = part
		} else {
			prefix = filepath.Join(prefix, part)
		}
		if err := anchor.Mkdir(prefix, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create profile directory component: %w", err)
		}
	}
	root, err := anchor.OpenRoot(relative)
	if err != nil {
		return nil, err
	}
	closeAnchor = false
	_ = anchor.Close()
	return root, nil
}

func rejectSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve profile directory: %w", err)
	}
	current := filepath.VolumeName(absolute) + string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(absolute, current), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return fmt.Errorf("inspect profile directory: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("profile directory cannot contain symlink components")
		}
	}
	return nil
}

func (s *Store) restrictDirectory() error {
	if s == nil || s.root == nil {
		return errors.New("profile root is unavailable")
	}
	if err := s.root.Chmod(".", 0o700); err != nil {
		return fmt.Errorf("restrict profile directory: %w", err)
	}
	info, err := s.root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect profile directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("profile directory is not a regular directory")
	}
	return nil
}

func (s *Store) load() (LoadReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := s.root.Lstat(fileName)
	if errors.Is(err, os.ErrNotExist) {
		return LoadReport{Initialized: true}, nil
	}
	if err != nil {
		return LoadReport{Error: "profile catalog cannot be inspected"}, fmt.Errorf("inspect profile catalog: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return s.recoverCorrupt(false)
	}
	file, err := s.root.Open(fileName)
	if err != nil {
		return LoadReport{Error: "profile catalog cannot be opened safely"}, fmt.Errorf("open profile catalog: %w", err)
	}
	closeFile := func() error {
		if file == nil {
			return nil
		}
		err := file.Close()
		file = nil
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = closeFile()
		return LoadReport{Error: "profile catalog permissions cannot be restricted"}, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil || len(raw) > maxFileBytes {
		_ = closeFile()
		return s.recoverCorrupt(false)
	}
	var candidate document
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&candidate); err != nil {
		_ = closeFile()
		return s.recoverCorrupt(false)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || candidate.SchemaVersion != domain.SchemaVersion || candidate.UpdatedAt.IsZero() {
		_ = closeFile()
		return s.recoverCorrupt(candidate.SchemaVersion != domain.SchemaVersion)
	}
	loaded := make(map[string]storedProfile, len(candidate.Profiles))
	for _, profile := range candidate.Profiles {
		if err := validateStored(profile); err != nil || profile.UpdatedAt.IsZero() {
			_ = closeFile()
			return s.recoverCorrupt(false)
		}
		if _, exists := loaded[profile.ID]; exists {
			_ = closeFile()
			return s.recoverCorrupt(false)
		}
		loaded[profile.ID] = profile
	}
	if len(loaded) > maxProfiles || validateFallbackGraph(loaded) != nil {
		_ = closeFile()
		return s.recoverCorrupt(false)
	}
	if err := closeFile(); err != nil {
		return LoadReport{Error: "profile catalog cannot be closed safely"}, fmt.Errorf("close profile catalog: %w", err)
	}
	s.profiles = loaded
	return LoadReport{}, nil
}

func (s *Store) recoverCorrupt(incompatible bool) (LoadReport, error) {
	stamp := s.now().UTC().Format("20060102T150405.000000000Z")
	for attempt := 0; attempt < 1000; attempt++ {
		suffix := ""
		if attempt > 0 {
			suffix = "-" + fmt.Sprint(attempt)
		}
		name := fileName + "." + stamp + suffix + ".corrupt"
		if _, err := s.root.Lstat(name); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			break
		}
		if err := s.root.Rename(fileName, name); err == nil {
			s.profiles = map[string]storedProfile{}
			return LoadReport{RecoveredCorrupt: true, QuarantinedPath: filepath.Join(s.dir, name), Error: "profile catalog was invalid; empty catalog loaded"}, nil
		}
	}
	return LoadReport{Error: "profile catalog was invalid; quarantine failed", RecoveredCorrupt: false, Incompatible: incompatible}, errors.New("profile catalog quarantine failed")
}

func validateStored(profile storedProfile) error {
	if !identifier.MatchString(profile.ID) || !validRemark(profile.Remark) {
		return ErrInvalid
	}
	validated, err := proxy.Validate(profile.ProxyURL)
	if err != nil || validated.URL.String() != profile.ProxyURL {
		return ErrInvalid
	}
	if err := validateFallbackFields(profile.ID, profile.FallbackMode, profile.FallbackProfileID, profile.FallbackAuthIndexes, profile.FallbackActive); err != nil {
		return err
	}
	return nil
}

func validateFallbackFields(id, mode, backupID string, authIndexes []string, active bool) error {
	mode = strings.TrimSpace(mode)
	backupID = strings.TrimSpace(backupID)
	if mode == "" {
		mode = domain.FallbackNone
	}
	switch mode {
	case domain.FallbackNone, domain.FallbackDirect:
		if backupID != "" {
			return ErrInvalid
		}
	case domain.FallbackProfile:
		if backupID == "" || backupID == id || !identifier.MatchString(backupID) {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if active && mode == domain.FallbackNone {
		return ErrInvalid
	}
	if active && len(authIndexes) == 0 {
		return ErrInvalid
	}
	if !active && len(authIndexes) > 0 {
		return ErrInvalid
	}
	if len(authIndexes) > maxProfiles {
		return ErrInvalid
	}
	seen := make(map[string]struct{}, len(authIndexes))
	for _, authIndex := range authIndexes {
		authIndex = strings.TrimSpace(authIndex)
		if authIndex == "" || len(authIndex) > 256 || strings.ContainsAny(authIndex, "\x00\r\n") {
			return ErrInvalid
		}
		if _, ok := seen[authIndex]; ok {
			return ErrInvalid
		}
		seen[authIndex] = struct{}{}
	}
	return nil
}

func validateFallbackGraph(profiles map[string]storedProfile) error {
	for id, profile := range profiles {
		if err := validateFallbackFields(id, profile.FallbackMode, profile.FallbackProfileID, profile.FallbackAuthIndexes, profile.FallbackActive); err != nil {
			return err
		}
		if profile.FallbackMode == domain.FallbackProfile {
			if _, ok := profiles[profile.FallbackProfileID]; !ok {
				return ErrInvalid
			}
		}
	}
	const (
		unseen = 0
		active = 1
		done   = 2
	)
	states := make(map[string]int, len(profiles))
	var visit func(string) error
	visit = func(id string) error {
		switch states[id] {
		case active:
			return ErrInvalid
		case done:
			return nil
		}
		states[id] = active
		profile := profiles[id]
		if profile.FallbackMode == domain.FallbackProfile {
			if err := visit(profile.FallbackProfileID); err != nil {
				return err
			}
		}
		states[id] = done
		return nil
	}
	for id := range profiles {
		if states[id] == unseen {
			if err := visit(id); err != nil {
				return err
			}
		}
	}
	return nil
}

func validRemark(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && len([]rune(trimmed)) <= maxRemarkLength && !strings.ContainsAny(trimmed, "\x00\r\n")
}

func duplicateRemark(profiles map[string]storedProfile, id, remark string) bool {
	for profileID, profile := range profiles {
		if profileID != id && strings.EqualFold(strings.TrimSpace(profile.Remark), strings.TrimSpace(remark)) {
			return true
		}
	}
	return false
}

func (s *Store) List() []domain.ProxyProfileProjection {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.ProxyProfileProjection, 0, len(s.profiles))
	for _, profile := range s.profiles {
		out = append(out, s.projection(profile))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Remark == out[j].Remark {
			return out[i].ID < out[j].ID
		}
		return out[i].Remark < out[j].Remark
	})
	return out
}

func (s *Store) Get(id string) (Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile, ok := s.profiles[strings.TrimSpace(id)]
	if !ok {
		return Profile{}, false
	}
	return s.toProfile(profile), true
}

func (s *Store) Match(rawURL string) (Profile, bool) {
	validated, err := proxy.Validate(rawURL)
	if err != nil {
		return Profile{}, false
	}
	canonical := validated.URL.String()
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, profile := range s.profiles {
		if profile.ProxyURL == canonical {
			return s.toProfile(profile), true
		}
	}
	return Profile{}, false
}

// Upsert creates a profile or replaces it with a validated URL. It remains
// available to in-process callers that have a complete URL; management routes
// use Save so an edit can deliberately retain the server-side URL.
func (s *Store) Upsert(id, remark, rawURL string) (Profile, error) {
	return s.save(id, remark, &rawURL, true, false, nil, nil)
}

// Save creates or updates a profile. For an existing profile, a nil or blank
// rawURL retains the catalog's current URL. The URL never leaves this store
// through a management projection.
func (s *Store) Save(id, remark string, rawURL *string) (Profile, error) {
	return s.save(id, remark, rawURL, false, true, nil, nil)
}

// SaveWithFallback updates the safe fallback configuration together with the
// profile. Nil fallback fields retain an existing setting on update and mean
// no fallback on create, preserving older callers and catalog documents.
func (s *Store) SaveWithFallback(id, remark string, rawURL, fallbackMode, fallbackProfileID *string) (Profile, error) {
	return s.save(id, remark, rawURL, false, true, fallbackMode, fallbackProfileID)
}

func (s *Store) save(id, remark string, rawURL *string, allowNamedCreate, retainExistingURL bool, fallbackMode, fallbackProfileID *string) (Profile, error) {
	id = strings.TrimSpace(id)
	remark = strings.TrimSpace(remark)
	if id != "" && !identifier.MatchString(id) {
		return Profile{}, ErrInvalid
	}
	if !validRemark(remark) {
		return Profile{}, ErrInvalid
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.profiles[id]
	if id != "" && !exists && !allowNamedCreate {
		return Profile{}, ErrNotFound
	}
	canonical := ""
	if rawURL != nil && strings.TrimSpace(*rawURL) != "" {
		validated, err := proxy.Validate(*rawURL)
		if err != nil {
			return Profile{}, fmt.Errorf("%w: proxy URL", ErrInvalid)
		}
		canonical = validated.URL.String()
	} else if exists && retainExistingURL {
		canonical = current.ProxyURL
	} else {
		return Profile{}, fmt.Errorf("%w: proxy URL", ErrInvalid)
	}
	if id == "" {
		id = newID()
	}
	mode := domain.FallbackNone
	backupID := ""
	if exists {
		mode = current.FallbackMode
		if mode == "" {
			mode = domain.FallbackNone
		}
		backupID = current.FallbackProfileID
	}
	if fallbackMode != nil {
		mode = strings.TrimSpace(*fallbackMode)
		if mode == "" {
			mode = domain.FallbackNone
		}
		if mode != domain.FallbackProfile {
			backupID = ""
		}
	}
	if fallbackProfileID != nil {
		backupID = strings.TrimSpace(*fallbackProfileID)
	}
	if mode != domain.FallbackProfile {
		backupID = ""
	}
	if exists && current.FallbackActive {
		currentMode := current.FallbackMode
		if currentMode == "" {
			currentMode = domain.FallbackNone
		}
		if mode != currentMode || backupID != current.FallbackProfileID {
			return Profile{}, ErrActiveFallback
		}
	}
	if err := validateFallbackFields(id, mode, backupID, nil, false); err != nil {
		return Profile{}, err
	}
	profile := storedProfile{ID: id, Remark: remark, ProxyURL: canonical, FallbackMode: mode, FallbackProfileID: backupID, UpdatedAt: s.now().UTC()}
	if exists && current.FallbackActive {
		profile.FallbackActive = true
		profile.FallbackAuthIndexes = append([]string(nil), current.FallbackAuthIndexes...)
	} else if exists && fallbackMode == nil && fallbackProfileID == nil {
		profile.FallbackActive = current.FallbackActive
		profile.FallbackAuthIndexes = append([]string(nil), current.FallbackAuthIndexes...)
	}
	if !exists && len(s.profiles) >= maxProfiles {
		return Profile{}, errors.New("proxy profile limit reached")
	}
	if duplicateRemark(s.profiles, id, remark) {
		return Profile{}, errors.New("proxy profile remark already exists")
	}
	next := cloneProfiles(s.profiles)
	next[id] = profile
	if err := validateFallbackGraph(next); err != nil {
		return Profile{}, err
	}
	if err := s.atomicWrite(next); err != nil {
		s.lastError = err
		return Profile{}, err
	}
	s.profiles = next
	s.lastError = nil
	return s.toProfile(profile), nil
}

func (s *Store) Delete(id string) error {
	id = strings.TrimSpace(id)
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.profiles[id]
	if !ok {
		return ErrNotFound
	}
	if profile.FallbackActive {
		return ErrActiveFallback
	}
	for profileID, profile := range s.profiles {
		if profileID != id && profile.FallbackMode == domain.FallbackProfile && profile.FallbackProfileID == id {
			return ErrReferenced
		}
	}
	next := cloneProfiles(s.profiles)
	delete(next, id)
	if err := s.atomicWrite(next); err != nil {
		s.lastError = err
		return err
	}
	s.profiles = next
	s.lastError = nil
	return nil
}

func (s *Store) projection(profile storedProfile) domain.ProxyProfileProjection {
	projection := domain.ProxyProfileProjection{ID: profile.ID, Remark: profile.Remark, FallbackMode: profile.FallbackMode}
	if projection.FallbackMode == "" {
		projection.FallbackMode = domain.FallbackNone
	}
	if profile.FallbackActive {
		projection.FallbackState = "active"
		projection.FallbackOriginalRemark = profile.Remark
		projection.FallbackAffectedCount = len(profile.FallbackAuthIndexes)
	} else if projection.FallbackMode != domain.FallbackNone {
		projection.FallbackState = "configured"
	} else {
		projection.FallbackState = "none"
	}
	if backup, ok := s.profiles[profile.FallbackProfileID]; ok && profile.FallbackMode == domain.FallbackProfile {
		projection.FallbackProfileRemark = backup.Remark
	}
	validated, err := proxy.Validate(profile.ProxyURL)
	if err != nil {
		return projection
	}
	projection.Endpoint = validated.Projection.Endpoint
	projection.Scheme = validated.Projection.Scheme
	projection.Host = validated.Projection.Host
	projection.Port = validated.Projection.Port
	return projection
}

func (s *Store) toProfile(profile storedProfile) Profile {
	return Profile{ID: profile.ID, Remark: profile.Remark, ProxyURL: profile.ProxyURL, FallbackMode: profile.FallbackMode, FallbackProfileID: profile.FallbackProfileID, FallbackAuthIndexes: append([]string(nil), profile.FallbackAuthIndexes...), Projection: s.projection(profile)}
}

// MarkFallback records a confirmed management-layer fallback for the supplied
// credential indexes. It does not intercept or alter CPA request routing.
func (s *Store) MarkFallback(id string, authIndexes []string) error {
	return s.updateFallbackState(id, authIndexes, true)
}

// ClearFallback removes only the supplied credentials from a profile's active
// fallback state. An empty active set returns the profile to configured state.
func (s *Store) ClearFallback(id string, authIndexes []string) error {
	return s.updateFallbackState(id, authIndexes, false)
}

func (s *Store) updateFallbackState(id string, authIndexes []string, activate bool) error {
	id = strings.TrimSpace(id)
	indexes := normalizeAuthIndexes(authIndexes)
	if len(indexes) == 0 {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	profile, ok := s.profiles[id]
	if !ok {
		return ErrNotFound
	}
	if profile.FallbackMode == "" || profile.FallbackMode == domain.FallbackNone {
		return ErrInvalid
	}
	next := cloneProfiles(s.profiles)
	current := append([]string(nil), profile.FallbackAuthIndexes...)
	if activate {
		current = appendUnique(current, indexes...)
		profile.FallbackActive = true
	} else {
		current = removeIndexes(current, indexes)
		profile.FallbackActive = len(current) > 0
	}
	profile.FallbackAuthIndexes = current
	profile.UpdatedAt = s.now().UTC()
	next[id] = profile
	if err := validateFallbackGraph(next); err != nil {
		return err
	}
	if err := s.atomicWrite(next); err != nil {
		s.lastError = err
		return err
	}
	s.profiles = next
	s.lastError = nil
	return nil
}

func normalizeAuthIndexes(indexes []string) []string {
	seen := make(map[string]struct{}, len(indexes))
	out := make([]string, 0, len(indexes))
	for _, value := range indexes {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 256 || strings.ContainsAny(value, "\x00\r\n") {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func appendUnique(base []string, values ...string) []string {
	return normalizeAuthIndexes(append(append([]string(nil), base...), values...))
}

func removeIndexes(base, remove []string) []string {
	blocked := make(map[string]struct{}, len(remove))
	for _, value := range remove {
		blocked[value] = struct{}{}
	}
	kept := make([]string, 0, len(base))
	for _, value := range base {
		if _, ok := blocked[value]; !ok {
			kept = append(kept, value)
		}
	}
	return normalizeAuthIndexes(kept)
}

func (s *Store) atomicWrite(next map[string]storedProfile) error {
	if s == nil || s.root == nil {
		return errors.New("profile store unavailable")
	}
	profiles := make([]storedProfile, 0, len(next))
	for _, profile := range next {
		profiles = append(profiles, profile)
	}
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].ID < profiles[j].ID })
	doc := document{SchemaVersion: domain.SchemaVersion, UpdatedAt: s.now().UTC(), Profiles: profiles}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil || len(raw) > maxFileBytes {
		return errors.New("proxy profile catalog is too large")
	}
	stamp := s.now().UTC().UnixNano()
	var tmpName string
	var file *os.File
	for attempt := 0; attempt < 1000; attempt++ {
		tmpName = fmt.Sprintf(".proxy-profiles-%d-%d.tmp", stamp, attempt)
		file, err = s.root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		break
	}
	if err != nil {
		return fmt.Errorf("create profile temporary file: %w", err)
	}
	remove := true
	defer func() {
		if remove {
			_ = s.root.Remove(tmpName)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := s.root.Rename(tmpName, fileName); err != nil {
		return fmt.Errorf("replace profile catalog atomically: %w", err)
	}
	remove = false
	if dir, err := s.root.Open("."); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func cloneProfiles(in map[string]storedProfile) map[string]storedProfile {
	out := make(map[string]storedProfile, len(in))
	for id, profile := range in {
		out[id] = profile
	}
	return out
}

func newID() string {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "profile-" + fmt.Sprint(time.Now().UnixNano())
	}
	return "profile-" + hex.EncodeToString(buf)
}

func (s *Store) LastError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastError
}

func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	root := s.root
	s.root = nil
	s.mu.Unlock()
	if root == nil {
		return nil
	}
	return root.Close()
}
