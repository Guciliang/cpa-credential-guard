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
	return domain.State{SchemaVersion: domain.SchemaVersion, UpdatedAt: now.UTC(), Credentials: map[string]domain.OwnershipRecord{}}
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
	defer file.Close()
	if err := restrictStateFile(file); err != nil {
		s.lastError = err
		return LoadReport{Error: "state file permissions cannot be restricted"}, fmt.Errorf("restrict state file: %w", err)
	}
	info, err = file.Stat()
	if err != nil {
		s.lastError = err
		return LoadReport{Error: "state file cannot be inspected"}, fmt.Errorf("stat opened state: %w", err)
	}
	if info.Size() > maxStateBytes {
		return s.recoverCorruptState(false)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxStateBytes+1))
	if err != nil {
		s.lastError = err
		return LoadReport{Error: "state file cannot be read"}, fmt.Errorf("read state: %w", err)
	}
	if len(raw) > maxStateBytes {
		return s.recoverCorruptState(false)
	}
	var candidate domain.State
	if err := decodeAndValidate(raw, &candidate); err != nil {
		return s.recoverCorruptState(errors.Is(err, errSchema))
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

func decodeAndValidate(raw []byte, dst *domain.State) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("state contains trailing data")
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
	if len(dst.Credentials) > maxStateRecords {
		return errors.New("state contains too many ownership records")
	}
	for key, record := range dst.Credentials {
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
		if err := validateProbeSummary(record.LastProbe); err != nil {
			return err
		}
	}
	return nil
}

func validateProbeSummary(probe *domain.ProbeSummary) error {
	if probe == nil {
		return nil
	}
	if probe.Status != domain.ProbeSuccess && probe.Status != domain.ProbeExhausted && probe.Status != domain.ProbeAmbiguous && probe.Status != domain.ProbeError {
		return errors.New("probe status is invalid")
	}
	if probe.SafeError != "" && domain.SafeCode(probe.SafeError) == "unknown" {
		return errors.New("probe error is not safe")
	}
	for _, window := range probe.Windows {
		if window.Family != domain.SafeFamily(window.Family) {
			return errors.New("probe family is not safe")
		}
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
		// never chmod-ed.
		if quarantined, err := s.root.OpenFile(name, os.O_RDWR, 0); err == nil {
			_ = quarantined.Chmod(0o600)
			_ = quarantined.Close()
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
	return record, ok
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
	if len(next.Credentials) > maxStateRecords {
		return errors.New("state contains too many ownership records")
	}
	for key, record := range next.Credentials {
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
		if record.LastProbe != nil {
			record.LastProbe = domain.SafeProbeSummary(record.LastProbe)
			next.Credentials[key] = record
		}
		if err := validateProbeSummary(record.LastProbe); err != nil {
			return err
		}
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

func cloneState(in domain.State) domain.State {
	out := in
	out.Credentials = make(map[string]domain.OwnershipRecord, len(in.Credentials))
	for key, value := range in.Credentials {
		out.Credentials[key] = value
		if value.LastProbe != nil {
			probe := *value.LastProbe
			probe.Windows = make([]domain.QuotaWindow, len(value.LastProbe.Windows))
			for index, window := range value.LastProbe.Windows {
				probe.Windows[index] = window
				if window.UsedPercent != nil {
					used := *window.UsedPercent
					probe.Windows[index].UsedPercent = &used
				}
				if window.Allowed != nil {
					allowed := *window.Allowed
					probe.Windows[index].Allowed = &allowed
				}
			}
			copyRecord := out.Credentials[key]
			copyRecord.LastProbe = &probe
			out.Credentials[key] = copyRecord
		}
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
