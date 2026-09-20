// Package state implements the versioned, fail-closed JSON state store.
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"cpa-credential-guard/internal/domain"
)

const (
	fileName        = "state.json"
	maxStateBytes   = 2 << 20
	maxStateRecords = 4096
	maxBackoffLevel = 32
)

var ErrUnavailable = errors.New("state store unavailable")

// Store serializes all writes and keeps a validated state snapshot in memory.
type Store struct {
	dir       string
	root      *os.Root
	now       func() time.Time
	mu        sync.RWMutex
	state     domain.State
	loaded    bool
	lastError error
}

// LoadReport records safe diagnostics without returning raw state contents.
type LoadReport struct {
	Initialized      bool
	QuarantinedPath  string
	RecoveredCorrupt bool
	Incompatible     bool
	Error            string
}

// New validates and creates the explicitly configured directory. It never
// substitutes a temporary directory or a process working-directory fallback.
func New(dir string) (*Store, LoadReport, error) {
	return NewWithClock(dir, time.Now)
}

func NewWithClock(dir string, now func() time.Time) (*Store, LoadReport, error) {
	if now == nil {
		now = time.Now
	}
	if err := validateDirPath(dir); err != nil {
		return nil, LoadReport{Error: err.Error()}, err
	}
	if err := rejectSymlinkComponents(dir); err != nil {
		return nil, LoadReport{Error: err.Error()}, err
	}
	root, err := openStateRoot(dir)
	if err != nil {
		return nil, LoadReport{Error: "state directory cannot be opened safely"}, fmt.Errorf("open state directory safely: %w", err)
	}
	s := &Store{dir: dir, root: root, now: now}
	if err := s.restrictDirectory(); err != nil {
		_ = root.Close()
		return nil, LoadReport{Error: err.Error()}, err
	}
	report, err := s.load()
	if err != nil {
		_ = root.Close()
		return nil, report, err
	}
	return s, report, nil
}

func validateDirPath(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("state directory is empty")
	}
	clean := filepath.Clean(dir)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return errors.New("state directory is unsafe")
	}
	if strings.ContainsAny(dir, "\x00\r\n") {
		return errors.New("state directory contains forbidden characters")
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve state directory: %w", err)
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
			return fmt.Errorf("inspect state directory: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("state directory cannot contain symlink components")
		}
	}
	return nil
}

// openStateRoot creates or opens the configured directory through an os.Root.
// Root operations are anchored to a directory handle and reject symlink
// components, so a path swap after validation cannot redirect state I/O to an
// attacker-selected target. The explicit symlink preflight remains useful for
// clear diagnostics, while Root provides the TOCTOU-resistant operation.
func openStateRoot(path string) (*os.Root, error) {
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
		return nil, errors.New("state directory must not be a filesystem root")
	}
	anchor, err := os.OpenRoot(anchorPath)
	if err != nil {
		return nil, fmt.Errorf("open state anchor: %w", err)
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
			return nil, errors.New("state directory escapes its anchor")
		}
		if prefix == "" {
			prefix = part
		} else {
			prefix = filepath.Join(prefix, part)
		}
		if err := anchor.Mkdir(prefix, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("create state directory component: %w", err)
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

func (s *Store) restrictDirectory() error {
	if s == nil || s.root == nil {
		return errors.New("state root is unavailable")
	}
	info, err := s.root.Stat(".")
	if err != nil {
		return fmt.Errorf("inspect state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory is not a regular directory")
	}
	if err := s.root.Chmod(".", 0o700); err != nil {
		return fmt.Errorf("restrict state directory: %w", err)
	}
	info, err = s.root.Stat(".")
	if err != nil {
		return fmt.Errorf("verify state directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("state directory changed to a non-directory")
	}
	return nil
}

func restrictStateFile(file *os.File) error {
	if file == nil {
		return errors.New("state file is unavailable")
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("state file is not a regular file")
	}
	// Chmod on an open descriptor cannot follow a path replacement. Do not
	// chmod the state path, which would reintroduce a symlink TOCTOU race.
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	info, err = file.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("state file changed to a non-regular file")
	}
	return nil
}

func emptyState(now time.Time) domain.State {
	return domain.State{SchemaVersion: domain.SchemaVersion, UpdatedAt: now.UTC(), Credentials: map[string]domain.OwnershipRecord{}, Observations: map[string]domain.CredentialObservation{}}
}

func (s *Store) load() (LoadReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.root == nil {
		return LoadReport{Error: "state root is unavailable"}, ErrUnavailable
	}
	info, lstatErr := s.root.Lstat(fileName)
	if errors.Is(lstatErr, os.ErrNotExist) {
		s.state = emptyState(s.now())
		s.loaded = true
		return LoadReport{Initialized: true}, nil
	}
	if lstatErr != nil {
		s.lastError = lstatErr
		return LoadReport{Error: "state file cannot be inspected"}, fmt.Errorf("lstat state: %w", lstatErr)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maxStateBytes {
		return s.recoverCorruptState(false)
	}

	// Root.OpenFile rejects a final symlink and pins the opened inode. Never
	// read or chmod the state path after a separate Lstat check.
	file, err := s.root.Open(fileName)
	if errors.Is(err, os.ErrNotExist) {
		s.state = emptyState(s.now())
		s.loaded = true
		return LoadReport{Initialized: true}, nil
	}
	if err != nil {
		s.lastError = err
		return LoadReport{Error: "state file cannot be opened safely"}, fmt.Errorf("open state: %w", err)
	}
	closeFile := func() error {
		if file == nil {
			return nil
		}
		err := file.Close()
		file = nil
		return err
	}
	if err := restrictStateFile(file); err != nil {
		_ = closeFile()
		s.lastError = err
		return LoadReport{Error: "state file permissions cannot be restricted"}, fmt.Errorf("restrict state file: %w", err)
	}
	info, err = file.Stat()
	if err != nil {
		_ = closeFile()
		s.lastError = err
		return LoadReport{Error: "state file cannot be inspected"}, fmt.Errorf("stat opened state: %w", err)
	}
	if info.Size() > maxStateBytes {
		_ = closeFile()
		return s.recoverCorruptState(false)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		_ = closeFile()
		s.lastError = err
		return LoadReport{Error: "state file cannot be read"}, fmt.Errorf("read state: %w", err)
	}
	if len(raw) > maxStateBytes {
		_ = closeFile()
		return s.recoverCorruptState(false)
	}
	var candidate domain.State
	if err := decodeAndValidate(raw, &candidate); err != nil {
		_ = closeFile()
		return s.recoverCorruptState(errors.Is(err, errSchema))
	}
	if err := closeFile(); err != nil {
		s.lastError = err
		return LoadReport{Error: "state file cannot be closed safely"}, fmt.Errorf("close state: %w", err)
	}
	if candidate.Credentials == nil {
		candidate.Credentials = map[string]domain.OwnershipRecord{}
	}
	s.state = candidate
	s.loaded = true
	return LoadReport{}, nil
}

func (s *Store) recoverCorruptState(incompatible bool) (LoadReport, error) {
	quarantined := s.quarantine()
	if quarantined == "" {
		err := errors.New("state file could not be quarantined safely")
		s.lastError = err
		return LoadReport{Incompatible: incompatible, Error: "state was invalid; quarantine failed"}, err
	}
	s.state = emptyState(s.now())
	s.loaded = true
	// A corrupt/incompatible state is safe to replace only after the original
	// has been preserved for diagnosis. If quarantine cannot be completed, the
	// caller stays inert instead of overwriting the only forensic copy.
	return LoadReport{RecoveredCorrupt: true, QuarantinedPath: quarantined, Incompatible: incompatible, Error: "state was invalid; safe empty state loaded"}, nil
}

var errSchema = errors.New("unsupported state schema")

type ownershipRecordWire struct {
	AuthIndex                     string          `json:"auth_index"`
	AuthID                        string          `json:"auth_id,omitempty"`
	FileName                      string          `json:"file_name"`
	DisabledAt                    time.Time       `json:"disabled_at"`
	WasEnabled                    bool            `json:"was_enabled"`
	ContentHashWithoutDisabled    string          `json:"content_hash_without_disabled"`
	PluginSaveHostRevision        string          `json:"plugin_save_host_revision,omitempty"`
	Phase                         string          `json:"phase"`
	AttemptID                     string          `json:"attempt_id"`
	PostEnableHashWithoutDisabled string          `json:"post_enable_hash_without_disabled,omitempty"`
	PostEnableHostRevision        string          `json:"post_enable_host_revision,omitempty"`
	ResetAt                       time.Time       `json:"reset_at,omitempty"`
	NextCheckAt                   time.Time       `json:"next_check_at,omitempty"`
	BackoffLevel                  int             `json:"backoff_level,omitempty"`
	LastReason                    string          `json:"last_reason,omitempty"`
	LastProbe                     json.RawMessage `json:"last_probe,omitempty"`
	Quota                         json.RawMessage `json:"quota,omitempty"`
	InitialWakeup                 json.RawMessage `json:"initial_wakeup,omitempty"`
	ResetWakeup                   json.RawMessage `json:"reset_wakeup,omitempty"`
}

type credentialObservationWire struct {
	AuthIndex       string          `json:"auth_index"`
	IdentityHash    string          `json:"identity_hash"`
	LastHealthCheck json.RawMessage `json:"last_health_check,omitempty"`
	Quota           json.RawMessage `json:"quota,omitempty"`
	InitialWakeup   json.RawMessage `json:"initial_wakeup,omitempty"`
	ResetWakeup     json.RawMessage `json:"reset_wakeup,omitempty"`
	Usage           json.RawMessage `json:"usage,omitempty"`
}

// decodeOptionalRecord deliberately treats an invalid optional sub-record as
// absent. The ownership identity/phase remains strict, while one damaged
// quota, probe, usage, or wake entry cannot quarantine unrelated credentials.
func decodeOptionalRecord[T any](raw json.RawMessage) *T {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var value T
	if err := decoder.Decode(&value); err != nil {
		return nil
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil
	}
	return &value
}

func decodeOwnershipRecord(raw json.RawMessage) (domain.OwnershipRecord, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var wire ownershipRecordWire
	if err := decoder.Decode(&wire); err != nil {
		return domain.OwnershipRecord{}, err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return domain.OwnershipRecord{}, errors.New("ownership record contains trailing data")
	}
	return domain.OwnershipRecord{
		AuthIndex: wire.AuthIndex, AuthID: wire.AuthID, FileName: wire.FileName,
		DisabledAt: wire.DisabledAt, WasEnabled: wire.WasEnabled,
		ContentHashWithoutDisabled: wire.ContentHashWithoutDisabled,
		PluginSaveHostRevision:     wire.PluginSaveHostRevision, Phase: wire.Phase,
		AttemptID: wire.AttemptID, PostEnableHashWithoutDisabled: wire.PostEnableHashWithoutDisabled,
		PostEnableHostRevision: wire.PostEnableHostRevision, ResetAt: wire.ResetAt,
		NextCheckAt: wire.NextCheckAt, BackoffLevel: wire.BackoffLevel, LastReason: wire.LastReason,
		LastProbe:     decodeOptionalRecord[domain.ProbeSummary](wire.LastProbe),
		Quota:         decodeOptionalRecord[domain.QuotaObservation](wire.Quota),
		InitialWakeup: decodeOptionalRecord[domain.WakeupRecord](wire.InitialWakeup),
		ResetWakeup:   decodeOptionalRecord[domain.WakeupRecord](wire.ResetWakeup),
	}, nil
}

func decodeAndValidate(raw []byte, dst *domain.State) error {
	// Keep optional observation and ownership sub-records raw while decoding the
	// required ownership identity strictly. A single malformed optional record
	// must be discarded without quarantining otherwise usable state.
	var envelope struct {
		SchemaVersion int                        `json:"schema_version"`
		UpdatedAt     time.Time                  `json:"updated_at"`
		Credentials   map[string]json.RawMessage `json:"credentials"`
		Observations  map[string]json.RawMessage `json:"observations"`
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("state contains trailing data")
	}
	dst.SchemaVersion = envelope.SchemaVersion
	dst.UpdatedAt = envelope.UpdatedAt
	if envelope.Credentials == nil {
		return errors.New("state credentials is required")
	}
	dst.Credentials = make(map[string]domain.OwnershipRecord, len(envelope.Credentials))
	for key, rawRecord := range envelope.Credentials {
		record, err := decodeOwnershipRecord(rawRecord)
		if err != nil {
			return err
		}
		dst.Credentials[key] = record
	}
	dst.Observations = make(map[string]domain.CredentialObservation, len(envelope.Observations))
	for key, rawObservation := range envelope.Observations {
		var observation domain.CredentialObservation
		observationDecoder := json.NewDecoder(bytes.NewReader(rawObservation))
		observationDecoder.DisallowUnknownFields()
		if err := observationDecoder.Decode(&observation); err != nil {
			continue
		}
		var observationExtra any
		if err := observationDecoder.Decode(&observationExtra); err != io.EOF {
			continue
		}
		if key != "codex:"+observation.AuthIndex {
			continue
		}
		if safeObservation, ok := domain.SafeCredentialObservation(observation); ok {
			dst.Observations[key] = safeObservation
		}
	}
	if dst.SchemaVersion != domain.SchemaVersion {
		return fmt.Errorf("%w: %d", errSchema, dst.SchemaVersion)
	}
	if dst.UpdatedAt.IsZero() {
		return errors.New("state updated_at is required")
	}
	if dst.Credentials == nil {
		return errors.New("state credentials is required")
	}
	if dst.Observations == nil {
		dst.Observations = map[string]domain.CredentialObservation{}
	}
	if len(dst.Observations) > maxStateRecords {
		return errors.New("state contains too many credential observations")
	}
	cleanObservations := make(map[string]domain.CredentialObservation, len(dst.Observations))
	for key, observation := range dst.Observations {
		if key != "codex:"+observation.AuthIndex {
			continue
		}
		if safeObservation, ok := domain.SafeCredentialObservation(observation); ok {
			cleanObservations[key] = safeObservation
		}
	}
	dst.Observations = cleanObservations
	if len(dst.Credentials) > maxStateRecords {
		return errors.New("state contains too many ownership records")
	}
	for key, record := range dst.Credentials {
		record.LastProbe = domain.SafeProbeSummary(record.LastProbe)
		record.Quota = domain.SafeQuotaObservation(record.Quota)
		record.InitialWakeup = domain.SafeWakeupRecord(record.InitialWakeup, domain.WakeupInitial)
		record.ResetWakeup = domain.SafeWakeupRecord(record.ResetWakeup, domain.WakeupReset)
		if key != "codex:"+record.AuthIndex || strings.TrimSpace(key) == "" || strings.TrimSpace(record.AuthIndex) == "" || strings.TrimSpace(record.FileName) == "" || strings.TrimSpace(record.AttemptID) == "" {
			return errors.New("state contains incomplete ownership record")
		}
		switch record.Phase {
		case domain.PhaseOwnedDisabled:
		case domain.PhaseRestorePending:
			// This phase is persisted before the enable save. It may not have a
			// post-enable guard yet; a restart treats an enabled credential as
			// unverifiable and moves it to manual_review.
		case domain.PhaseProbePending:
			if strings.TrimSpace(record.PostEnableHashWithoutDisabled) == "" || strings.TrimSpace(record.PostEnableHostRevision) == "" {
				return errors.New("pending recovery lacks post-enable guard")
			}
		case domain.PhaseManualReview:
		default:
			return fmt.Errorf("unknown ownership phase %q", record.Phase)
		}
		if strings.TrimSpace(record.ContentHashWithoutDisabled) == "" {
			return errors.New("ownership hash is required")
		}
		if record.BackoffLevel < 0 || record.BackoffLevel > maxBackoffLevel {
			return errors.New("backoff level is out of range")
		}
		if record.LastReason != "" && domain.SafeCode(record.LastReason) == "unknown" {
			return errors.New("ownership reason is not safe")
		}
		if record.Quota != nil {
			if record.Quota.Status != domain.QuotaUnknown && record.Quota.Status != domain.QuotaAvailable && record.Quota.Status != domain.QuotaExhausted {
				return errors.New("quota status is invalid")
			}
			if len(record.Quota.IdentityHash) > 128 || record.Quota.SafeError != "" && domain.SafeCode(record.Quota.SafeError) == "unknown" {
				return errors.New("quota observation is not safe")
			}
			if record.Quota.AuthIndex != record.AuthIndex || record.Quota.IdentityHash != record.ContentHashWithoutDisabled {
				record.Quota = nil
			}
		}
		if record.InitialWakeup != nil && record.InitialWakeup.IdentityHash != record.ContentHashWithoutDisabled {
			record.InitialWakeup = nil
		}
		if record.ResetWakeup != nil && record.ResetWakeup.IdentityHash != record.ContentHashWithoutDisabled {
			record.ResetWakeup = nil
		}
		dst.Credentials[key] = record
	}
	return nil
}

func (s *Store) quarantine() string {
	if s == nil || s.root == nil {
		return ""
	}
	stamp := strconv.FormatInt(s.now().UTC().UnixNano(), 10)
	for attempt := 0; attempt < 1000; attempt++ {
		suffix := ""
		if attempt > 0 {
			suffix = "-" + strconv.Itoa(attempt)
		}
		name := fileName + "." + stamp + suffix + ".corrupt"
		if _, err := s.root.Lstat(name); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return ""
		}
		// Rename is performed relative to the pinned directory handle. It moves
		// a symlink itself rather than following its target, and cannot be
		// redirected by replacing the state directory path.
		if err := s.root.Rename(fileName, name); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue
			}
			return ""
		}
		// Restrict a regular quarantined file through an open descriptor. A
		// quarantined symlink is intentionally left untouched so its target is
		// never chmod-ed; the pinned Root open also rejects a final symlink.
		if quarantinedInfo, statErr := s.root.Lstat(name); statErr == nil && quarantinedInfo.Mode().IsRegular() && quarantinedInfo.Mode()&os.ModeSymlink == 0 {
			if quarantined, openErr := s.root.OpenFile(name, os.O_RDWR, 0); openErr == nil {
				_ = quarantined.Chmod(0o600)
				_ = quarantined.Close()
			}
		}
		return filepath.Join(s.dir, name)
	}
	return ""
}

// Snapshot returns a copy suitable for in-process inspection.
func (s *Store) Snapshot() domain.State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneState(s.state)
}

// Get returns one ownership record.
func (s *Store) Get(key string) (domain.OwnershipRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	record, ok := s.state.Credentials[key]
	if !ok {
		return domain.OwnershipRecord{}, false
	}
	return cloneOwnershipRecord(record), true
}

// GetObservation returns one safe optional observation snapshot.
func (s *Store) GetObservation(key string) (domain.CredentialObservation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	observation, ok := s.state.Observations[key]
	return cloneObservation(observation), ok
}

// Replace replaces the full validated state and persists it atomically.
func (s *Store) Replace(next domain.State) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := validateStateForSave(&next); err != nil {
		return err
	}
	next.UpdatedAt = s.now().UTC()
	if next.SchemaVersion == 0 {
		next.SchemaVersion = domain.SchemaVersion
	}
	if err := s.atomicWrite(next); err != nil {
		s.lastError = err
		return err
	}
	s.state = cloneState(next)
	s.loaded = true
	s.lastError = nil
	return nil
}

// Update applies one serialized mutation and writes it atomically. The
// callback operates on a private copy, so a failed write cannot partially
// alter the in-memory snapshot.
func (s *Store) Update(fn func(*domain.State) error) error {
	if fn == nil {
		return errors.New("state update callback is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	next := cloneState(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	if err := validateStateForSave(&next); err != nil {
		return err
	}
	next.UpdatedAt = s.now().UTC()
	if err := s.atomicWrite(next); err != nil {
		s.lastError = err
		return err
	}
	s.state = cloneState(next)
	s.loaded = true
	s.lastError = nil
	return nil
}

func validateStateForSave(next *domain.State) error {
	if next == nil {
		return errors.New("state is nil")
	}
	if next.SchemaVersion == 0 {
		next.SchemaVersion = domain.SchemaVersion
	}
	if next.SchemaVersion != domain.SchemaVersion {
		return errSchema
	}
	if next.Credentials == nil {
		next.Credentials = map[string]domain.OwnershipRecord{}
	}
	if next.Observations == nil {
		next.Observations = map[string]domain.CredentialObservation{}
	}
	if len(next.Observations) > maxStateRecords {
		return errors.New("state contains too many credential observations")
	}
	cleanObservations := make(map[string]domain.CredentialObservation, len(next.Observations))
	for key, observation := range next.Observations {
		if key != "codex:"+observation.AuthIndex {
			continue
		}
		if safeObservation, ok := domain.SafeCredentialObservation(observation); ok {
			cleanObservations[key] = safeObservation
		}
	}
	next.Observations = cleanObservations
	if len(next.Credentials) > maxStateRecords {
		return errors.New("state contains too many ownership records")
	}
	for key, record := range next.Credentials {
		record.Quota = domain.SafeQuotaObservation(record.Quota)
		record.InitialWakeup = domain.SafeWakeupRecord(record.InitialWakeup, domain.WakeupInitial)
		record.ResetWakeup = domain.SafeWakeupRecord(record.ResetWakeup, domain.WakeupReset)
		if record.Quota != nil && (record.Quota.AuthIndex != record.AuthIndex || record.Quota.IdentityHash != record.ContentHashWithoutDisabled) {
			record.Quota = nil
		}
		if record.InitialWakeup != nil && record.InitialWakeup.IdentityHash != record.ContentHashWithoutDisabled {
			record.InitialWakeup = nil
		}
		if record.ResetWakeup != nil && record.ResetWakeup.IdentityHash != record.ContentHashWithoutDisabled {
			record.ResetWakeup = nil
		}
		if key != "codex:"+record.AuthIndex || strings.TrimSpace(key) == "" || strings.TrimSpace(record.AuthIndex) == "" || strings.TrimSpace(record.FileName) == "" || strings.TrimSpace(record.AttemptID) == "" {
			return errors.New("ownership record is incomplete")
		}
		if strings.TrimSpace(record.ContentHashWithoutDisabled) == "" {
			return errors.New("ownership hash is required")
		}
		switch record.Phase {
		case domain.PhaseOwnedDisabled, domain.PhaseManualReview:
		case domain.PhaseRestorePending:
		case domain.PhaseProbePending:
			if record.PostEnableHostRevision == "" || record.PostEnableHashWithoutDisabled == "" {
				return errors.New("pending recovery guard is incomplete")
			}
		default:
			return fmt.Errorf("unknown ownership phase %q", record.Phase)
		}
		if record.BackoffLevel < 0 || record.BackoffLevel > maxBackoffLevel {
			return errors.New("backoff level is out of range")
		}
		if record.LastReason != "" && domain.SafeCode(record.LastReason) == "unknown" {
			return errors.New("ownership reason is not safe")
		}
		record.LastProbe = domain.SafeProbeSummary(record.LastProbe)
		next.Credentials[key] = record
	}
	return nil
}

func (s *Store) atomicWrite(next domain.State) error {
	raw, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	if len(raw) > maxStateBytes {
		return errors.New("encoded state exceeds size limit")
	}
	if err := s.restrictDirectory(); err != nil {
		return err
	}
	tmp, tmpName, err := s.createTemp()
	if err != nil {
		return fmt.Errorf("create state temporary file: %w", err)
	}
	remove := true
	defer func() {
		if remove {
			_ = s.root.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("restrict state temporary file: %w", err)
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write state temporary file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync state temporary file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close state temporary file: %w", err)
	}
	if err := s.root.Rename(tmpName, fileName); err != nil {
		return fmt.Errorf("replace state atomically: %w", err)
	}
	remove = false
	// Sync the pinned directory descriptor rather than reopening the mutable
	// directory path. The renamed file already has mode 0600.
	if dir, err := s.root.Open("."); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func (s *Store) createTemp() (*os.File, string, error) {
	if s == nil || s.root == nil {
		return nil, "", ErrUnavailable
	}
	stamp := strconv.FormatInt(s.now().UTC().UnixNano(), 10)
	for attempt := 0; attempt < 1000; attempt++ {
		name := ".state-" + stamp + "-" + strconv.Itoa(attempt) + ".tmp"
		file, err := s.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if errors.Is(err, os.ErrExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		return file, name, nil
	}
	return nil, "", errors.New("could not allocate a unique state temporary file")
}

func cloneWindows(in []domain.QuotaWindow) []domain.QuotaWindow {
	out := make([]domain.QuotaWindow, len(in))
	for index, window := range in {
		out[index] = window
		if window.UsedPercent != nil {
			value := *window.UsedPercent
			out[index].UsedPercent = &value
		}
		if window.Allowed != nil {
			value := *window.Allowed
			out[index].Allowed = &value
		}
	}
	return out
}

func cloneObservation(in domain.CredentialObservation) domain.CredentialObservation {
	out := in
	if in.LastHealthCheck != nil {
		probe := *in.LastHealthCheck
		probe.Windows = cloneWindows(in.LastHealthCheck.Windows)
		out.LastHealthCheck = &probe
	}
	if in.Quota != nil {
		quota := *in.Quota
		quota.Windows = cloneWindows(in.Quota.Windows)
		out.Quota = &quota
	}
	if in.InitialWakeup != nil {
		wake := *in.InitialWakeup
		out.InitialWakeup = &wake
	}
	if in.ResetWakeup != nil {
		wake := *in.ResetWakeup
		out.ResetWakeup = &wake
	}
	if in.Usage != nil {
		usage := *in.Usage
		out.Usage = &usage
	}
	return out
}

func cloneOwnershipRecord(in domain.OwnershipRecord) domain.OwnershipRecord {
	out := in
	if in.LastProbe != nil {
		probe := *in.LastProbe
		probe.Windows = cloneWindows(in.LastProbe.Windows)
		out.LastProbe = &probe
	}
	if in.Quota != nil {
		quota := *in.Quota
		quota.Windows = cloneWindows(in.Quota.Windows)
		out.Quota = &quota
	}
	if in.InitialWakeup != nil {
		wake := *in.InitialWakeup
		out.InitialWakeup = &wake
	}
	if in.ResetWakeup != nil {
		wake := *in.ResetWakeup
		out.ResetWakeup = &wake
	}
	return out
}

func cloneState(in domain.State) domain.State {
	out := in
	out.Credentials = make(map[string]domain.OwnershipRecord, len(in.Credentials))
	out.Observations = make(map[string]domain.CredentialObservation, len(in.Observations))
	for key, value := range in.Observations {
		out.Observations[key] = cloneObservation(value)
	}
	for key, value := range in.Credentials {
		out.Credentials[key] = cloneOwnershipRecord(value)
	}
	return out
}

// Close releases the pinned state-directory handle. It is safe to call more
// than once and prevents reconfiguration from retaining an old controller's
// directory descriptor indefinitely.
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

func (s *Store) LastError() error { s.mu.RLock(); defer s.mu.RUnlock(); return s.lastError }
func (s *Store) Dir() string      { return s.dir }
