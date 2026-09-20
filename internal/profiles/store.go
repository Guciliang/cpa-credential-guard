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
	ErrNotFound = errors.New("proxy profile not found")
	ErrInvalid  = errors.New("proxy profile is invalid")
	identifier  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,95}$`)
)

type storedProfile struct {
	ID        string    `json:"id"`
	Remark    string    `json:"remark"`
	ProxyURL  string    `json:"proxy_url"`
	UpdatedAt time.Time `json:"updated_at"`
}

type document struct {
	SchemaVersion int             `json:"schema_version"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Profiles      []storedProfile `json:"profiles"`
}

// Profile is an in-process profile. ProxyURL never crosses the management
// response boundary; callers should use Projection for UI/API data.
type Profile struct {
	ID         string
	Remark     string
	ProxyURL   string
	Projection domain.ProxyProfileProjection
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
	if len(loaded) > maxProfiles {
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

func (s *Store) Upsert(id, remark, rawURL string) (Profile, error) {
	id = strings.TrimSpace(id)
	remark = strings.TrimSpace(remark)
	if id != "" && !identifier.MatchString(id) {
		return Profile{}, ErrInvalid
	}
	if !validRemark(remark) {
		return Profile{}, ErrInvalid
	}
	validated, err := proxy.Validate(rawURL)
	if err != nil {
		return Profile{}, fmt.Errorf("%w: proxy URL", ErrInvalid)
	}
	canonical := validated.URL.String()
	if id == "" {
		id = newID()
	}
	profile := storedProfile{ID: id, Remark: remark, ProxyURL: canonical, UpdatedAt: s.now().UTC()}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.profiles[id]; !exists && len(s.profiles) >= maxProfiles {
		return Profile{}, errors.New("proxy profile limit reached")
	}
	if duplicateRemark(s.profiles, id, remark) {
		return Profile{}, errors.New("proxy profile remark already exists")
	}
	next := cloneProfiles(s.profiles)
	next[id] = profile
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
	if _, ok := s.profiles[id]; !ok {
		return ErrNotFound
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
	validated, err := proxy.Validate(profile.ProxyURL)
	if err != nil {
		return domain.ProxyProfileProjection{ID: profile.ID, Remark: profile.Remark}
	}
	return domain.ProxyProfileProjection{ID: profile.ID, Remark: profile.Remark, Endpoint: validated.Projection.Endpoint, Scheme: validated.Projection.Scheme, Host: validated.Projection.Host, Port: validated.Projection.Port}
}

func (s *Store) toProfile(profile storedProfile) Profile {
	return Profile{ID: profile.ID, Remark: profile.Remark, ProxyURL: profile.ProxyURL, Projection: s.projection(profile)}
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
