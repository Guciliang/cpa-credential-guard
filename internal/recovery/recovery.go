// Package recovery owns the conservative enable -> one health probe -> retain or
// re-disable state machine. It never selects credentials for normal CPA traffic.
package recovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"cpa-credential-guard/internal/codexhealth"
	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/state"
)

const maxRecoveryBackoffLevel = 32

type Prober interface {
	Probe(context.Context, []byte) (domain.ProbeSummary, error)
}

type Config struct {
	Enabled        bool
	ProbeEnabled   bool
	ScanInterval   time.Duration
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type Manager struct {
	store    *state.Store
	repo     *credentials.Repository
	prober   Prober
	cfg      Config
	now      func() time.Time
	workerMu sync.Mutex
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

func New(store *state.Store, repo *credentials.Repository, prober Prober, cfg Config) *Manager {
	return NewWithClock(store, repo, prober, cfg, time.Now)
}
func NewWithClock(store *state.Store, repo *credentials.Repository, prober Prober, cfg Config, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 15 * time.Minute
	}
	if cfg.MaxBackoff < cfg.InitialBackoff {
		cfg.MaxBackoff = cfg.InitialBackoff
	}
	return &Manager{store: store, repo: repo, prober: prober, cfg: cfg, now: now}
}

// Enabled reports whether an explicit recovery scan can actually run. The
// management route uses this to avoid claiming a scan started for an inert or
// partially constructed manager.
func (m *Manager) Enabled() bool {
	return m != nil && m.cfg.Enabled && m.cfg.ProbeEnabled && m.store != nil && m.repo != nil
}

func (m *Manager) Start(parent context.Context) {
	if m == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	m.workerMu.Lock()
	defer m.workerMu.Unlock()
	if m.cancel != nil || !m.cfg.Enabled || m.store == nil || m.repo == nil || !m.cfg.ProbeEnabled || m.cfg.ScanInterval <= 0 {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.cancel = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(m.cfg.ScanInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = m.Scan(ctx)
			}
		}
	}()
}
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.workerMu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.workerMu.Unlock()
	if cancel != nil {
		cancel()
		m.wg.Wait()
	}
}

// Scan processes due owned records. It is safe to call concurrently; the
// shared per-auth lock and a fresh state read prevent duplicate probes.
func (m *Manager) Scan(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if m == nil || m.store == nil || m.repo == nil || !m.cfg.Enabled || !m.cfg.ProbeEnabled {
		return nil
	}
	var scanErr error
	for key, record := range m.store.Snapshot().Credentials {
		if !m.due(record) {
			continue
		}
		index := record.AuthIndex
		if err := m.repo.WithLock(ctx, index, func() error { return m.processLocked(ctx, key) }); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Individual credentials are independent. Keep scanning and leave a
			// safe record rather than aborting a batch on one Host error. Return
			// the first safe error after the batch so callers can report that the
			// scan was incomplete without hiding later credentials' results.
			if safeErr := m.recordSafeError(key, record, "host_error"); safeErr != nil && scanErr == nil {
				scanErr = safeErr
			} else if scanErr == nil {
				scanErr = err
			}
		}
	}
	return scanErr
}

func (m *Manager) due(record domain.OwnershipRecord) bool {
	return record.NextCheckAt.IsZero() || !m.now().Before(record.NextCheckAt)
}

func (m *Manager) processLocked(ctx context.Context, key string) error {
	record, ok := m.store.Get(key)
	if !ok || !m.due(record) {
		return nil
	}
	if record.Phase == domain.PhaseManualReview || !record.WasEnabled {
		return nil
	}
	snap, err := m.repo.Snapshot(ctx, record.AuthIndex)
	if err != nil {
		return err
	}
	defer wipeCredentialJSON(snap.JSON)
	if snap.AuthIndex != record.AuthIndex || (record.AuthID != "" && snap.Runtime.ID != "" && snap.Runtime.ID != record.AuthID) || (record.FileName != "" && snap.Name != "" && snap.Name != record.FileName) {
		return m.retire(key)
	}
	if record.AuthID != "" && snap.RuntimeOK && snap.Runtime.ID == "" {
		return m.manualReview(key, record, "ownership_guard_failed")
	}
	switch record.Phase {
	case domain.PhaseOwnedDisabled:
		return m.startRecoveryLocked(ctx, key, record, snap)
	case domain.PhaseRestorePending:
		// This phase was persisted before enabling. After a restart there is no
		// post-enable revision to prove ownership. A still-disabled credential
		// can safely retry; an enabled one is moved to manual review.
		if snap.Disabled {
			return m.startRecoveryLocked(ctx, key, record, snap)
		}
		return m.manualReview(key, record, "unverifiable_pending_enable")
	case domain.PhaseProbePending:
		if !snap.RuntimeOK || snap.Revision == "" || snap.ContentHashWithoutDisabled == "" {
			return m.manualReview(key, record, "post_enable_guard_unavailable")
		}
		if snap.Disabled {
			return m.retire(key)
		}
		if !guardMatchesPostEnable(snap, record) {
			return m.retire(key)
		}
		return m.probeLocked(ctx, key, record, snap)
	default:
		return m.manualReview(key, record, "unknown_phase")
	}
}

func (m *Manager) startRecoveryLocked(ctx context.Context, key string, record domain.OwnershipRecord, snap credentials.Snapshot) error {
	if !snap.Disabled {
		return m.retire(key)
	}
	if record.PluginSaveHostRevision == "" || !snap.RuntimeOK || snap.Revision == "" {
		return m.manualReview(key, record, "disable_revision_unavailable")
	}
	if snap.ContentHashWithoutDisabled != record.ContentHashWithoutDisabled {
		return m.retire(key)
	}
	if record.PluginSaveHostRevision != "" && (!snap.RuntimeOK || snap.Revision.String() != record.PluginSaveHostRevision) {
		return m.retire(key)
	}
	if err := m.store.Update(func(next *domain.State) error {
		current, exists := next.Credentials[key]
		if !exists {
			return nil
		}
		current.Phase = domain.PhaseRestorePending
		current.AttemptID = newAttemptID()
		current.LastReason = record.LastReason
		next.Credentials[key] = current
		return nil
	}); err != nil {
		return err
	}
	pending, ok := m.store.Get(key)
	if !ok {
		// The ownership record may have been retired while the state transition
		// was being committed. Never mutate a credential without the durable
		// record that authorizes this recovery attempt.
		return nil
	}
	guard := credentials.Guard{ContentHashWithoutDisabled: record.ContentHashWithoutDisabled, HostRevision: credentials.RuntimeRevision(record.PluginSaveHostRevision), RequireRuntime: true}
	result, err := m.repo.SetDisabledLocked(ctx, record.AuthIndex, false, guard)
	defer wipeCredentialJSON(result.Before.JSON)
	defer wipeCredentialJSON(result.After.JSON)
	if err != nil {
		return m.retryOrReview(key, pending, nil, err)
	}
	if !result.After.RuntimeOK || result.After.Revision == "" || result.After.ContentHashWithoutDisabled == "" {
		return m.manualReview(key, pending, "post_enable_revision_unavailable")
	}
	if err := m.store.Update(func(next *domain.State) error {
		current, exists := next.Credentials[key]
		if !exists {
			return nil
		}
		current.Phase = domain.PhaseProbePending
		current.PostEnableHashWithoutDisabled = result.After.ContentHashWithoutDisabled
		current.PostEnableHostRevision = result.After.Revision.String()
		next.Credentials[key] = current
		return nil
	}); err != nil {
		return err
	}
	pending, ok = m.store.Get(key)
	if !ok {
		return nil
	}
	return m.probeLocked(ctx, key, pending, result.After)
}

func (m *Manager) probeLocked(ctx context.Context, key string, record domain.OwnershipRecord, snap credentials.Snapshot) error {
	defer wipeCredentialJSON(snap.JSON)
	if !m.proberIsAvailable() {
		// A pending enable without a probe adapter is still a failed attempt;
		// fail closed through the guarded re-disable path below.
		summary := domain.ProbeSummary{At: m.now().UTC(), Status: domain.ProbeError, SafeError: "probe_unavailable"}
		return m.finishFailedProbe(ctx, key, record, summary)
	}
	if !snap.RuntimeOK || snap.Revision == "" || snap.ContentHashWithoutDisabled == "" {
		return m.manualReview(key, record, "post_enable_guard_unavailable")
	}
	if snap.Disabled {
		return m.retire(key)
	}
	if !guardMatchesPostEnable(snap, record) {
		return m.retire(key)
	}
	summary, err := m.prober.Probe(ctx, snap.JSON)
	if err != nil {
		summary = domain.ProbeSummary{At: m.now().UTC(), Status: domain.ProbeError, SafeError: "probe_error"}
	}
	if summary.At.IsZero() {
		summary.At = m.now().UTC()
	}
	if summary.Status == "" {
		summary.Status = domain.ProbeError
	}
	if summary.SafeError == "" {
		summary.SafeError = "probe_error"
	}
	safeSummary := domain.SafeProbeSummary(&summary)
	if safeSummary != nil {
		summary = *safeSummary
		if summary.SafeError == "unknown" {
			summary.SafeError = "probe_error"
		}
	}
	if summary.Status == domain.ProbeSuccess {
		current, getErr := m.repo.Snapshot(ctx, record.AuthIndex)
		if getErr != nil {
			return getErr
		}
		defer wipeCredentialJSON(current.JSON)
		if !current.RuntimeOK || current.Revision == "" || current.ContentHashWithoutDisabled == "" {
			return m.manualReview(key, record, "post_enable_guard_unavailable")
		}
		if current.Disabled {
			return m.retire(key)
		}
		if !guardMatchesPostEnable(current, record) {
			return m.retire(key)
		}
		if err := m.recordHealthCheck(key, record.AuthIndex, current.ContentHashWithoutDisabled, summary); err != nil {
			return err
		}
		return m.retire(key)
	}
	return m.finishFailedProbe(ctx, key, record, summary)
}

func (m *Manager) finishFailedProbe(ctx context.Context, key string, record domain.OwnershipRecord, summary domain.ProbeSummary) error {
	current, getErr := m.repo.Snapshot(ctx, record.AuthIndex)
	if getErr != nil {
		return getErr
	}
	defer wipeCredentialJSON(current.JSON)
	if !current.RuntimeOK || current.Revision == "" || current.ContentHashWithoutDisabled == "" {
		return m.manualReview(key, record, "post_enable_guard_unavailable")
	}
	if current.Disabled {
		return m.retire(key)
	}
	if !guardMatchesPostEnable(current, record) {
		return m.retire(key)
	}
	result, saveErr := m.repo.SetDisabledLocked(ctx, record.AuthIndex, true, credentials.Guard{ContentHashWithoutDisabled: record.PostEnableHashWithoutDisabled, HostRevision: credentials.RuntimeRevision(record.PostEnableHostRevision), RequireRuntime: true})
	defer wipeCredentialJSON(result.Before.JSON)
	defer wipeCredentialJSON(result.After.JSON)
	if saveErr != nil {
		return m.manualReview(key, record, "redisable_failed")
	}
	if !result.After.RuntimeOK || result.After.Revision == "" || result.After.ContentHashWithoutDisabled == "" {
		return m.manualReview(key, record, "redisable_revision_unavailable")
	}
	level := record.BackoffLevel
	if level < 0 {
		level = 0
	}
	if level < maxRecoveryBackoffLevel {
		level++
	}
	delay := m.backoffForLevel(level)
	nextCheckAt := addBackoff(m.now(), delay)
	return m.store.Update(func(next *domain.State) error {
		current, exists := next.Credentials[key]
		if !exists {
			return nil
		}
		current.Phase = domain.PhaseOwnedDisabled
		current.BackoffLevel = level
		current.NextCheckAt = nextCheckAt
		current.LastProbe = &summary
		current.LastReason = summary.SafeError
		current.ContentHashWithoutDisabled = result.After.ContentHashWithoutDisabled
		current.PluginSaveHostRevision = result.After.Revision.String()
		current.PostEnableHashWithoutDisabled = ""
		current.PostEnableHostRevision = ""
		next.Credentials[key] = current
		return nil
	})
}

func (m *Manager) backoffForLevel(level int) time.Duration {
	if level < 1 {
		level = 1
	}
	if level > maxRecoveryBackoffLevel {
		level = maxRecoveryBackoffLevel
	}
	initial := m.cfg.InitialBackoff
	if initial <= 0 {
		initial = 15 * time.Minute
	}
	maximum := m.cfg.MaxBackoff
	if maximum <= 0 || maximum < initial {
		maximum = initial
	}
	delay := initial
	for i := 1; i < level; i++ {
		if delay >= maximum {
			return maximum
		}
		// Check before multiplying so a large configured duration cannot
		// overflow time.Duration and become an immediate retry.
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	if delay > maximum {
		return maximum
	}
	return delay
}

func addBackoff(now time.Time, delay time.Duration) time.Time {
	if delay <= 0 {
		return now.UTC()
	}
	next := now.Add(delay)
	// A pathological injected clock near time.Time's upper bound must not
	// wrap into the past and create a hot retry loop.
	if !next.After(now) {
		return time.Unix(1<<63-1, 999999999).UTC()
	}
	return next.UTC()
}

func (m *Manager) scheduleBackoff(record *domain.OwnershipRecord) {
	if record == nil {
		return
	}
	level := record.BackoffLevel
	if level < 0 {
		level = 0
	}
	if level < maxRecoveryBackoffLevel {
		level++
	}
	record.BackoffLevel = level
	record.NextCheckAt = addBackoff(m.now(), m.backoffForLevel(level))
}

func (m *Manager) proberIsAvailable() bool { return m != nil && m.prober != nil }

func guardMatchesPostEnable(snap credentials.Snapshot, record domain.OwnershipRecord) bool {
	return snap.RuntimeOK && snap.Revision != "" && !snap.Disabled &&
		(record.AuthID == "" || snap.AuthID == record.AuthID) &&
		snap.ContentHashWithoutDisabled == record.PostEnableHashWithoutDisabled && snap.Revision.String() == record.PostEnableHostRevision
}
func (m *Manager) recordHealthCheck(key, authIndex, identityHash string, summary domain.ProbeSummary) error {
	safeSummary := domain.SafeProbeSummary(&summary)
	if safeSummary == nil {
		safeSummary = &domain.ProbeSummary{At: m.now().UTC(), Status: domain.ProbeError, SafeError: "probe_error"}
	}
	return m.store.Update(func(next *domain.State) error {
		if next.Observations == nil {
			next.Observations = map[string]domain.CredentialObservation{}
		}
		observation := next.Observations[key]
		if observation.AuthIndex != authIndex || observation.IdentityHash != identityHash {
			observation = domain.CredentialObservation{AuthIndex: authIndex, IdentityHash: identityHash}
		}
		probe := *safeSummary
		probe.Windows = domain.SafeQuotaWindows(safeSummary.Windows)
		observation.LastHealthCheck = &probe
		quotaObservation := codexhealth.QuotaObservationFromProbe(authIndex, identityHash, probe)
		observation.Quota = &quotaObservation
		next.Observations[key] = observation
		return nil
	})
}

func (m *Manager) retire(key string) error {
	return m.store.Update(func(next *domain.State) error { delete(next.Credentials, key); return nil })
}
func (m *Manager) manualReview(key string, record domain.OwnershipRecord, reason string) error {
	return m.store.Update(func(next *domain.State) error {
		current, ok := next.Credentials[key]
		if !ok {
			return nil
		}
		current.Phase = domain.PhaseManualReview
		current.LastReason = reason
		current.LastProbe = record.LastProbe
		next.Credentials[key] = current
		return nil
	})
}
func (m *Manager) retryOrReview(key string, record domain.OwnershipRecord, summary *domain.ProbeSummary, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, credentials.ErrRevisionUnavailable) || errors.Is(err, credentials.ErrRevisionMismatch) {
		return m.manualReview(key, record, "ownership_guard_failed")
	}
	if summary != nil {
		record.LastProbe = summary
	}
	m.scheduleBackoff(&record)
	record.LastReason = "recovery_error"
	return m.store.Update(func(next *domain.State) error {
		if _, ok := next.Credentials[key]; ok {
			next.Credentials[key] = record
		}
		return nil
	})
}
func (m *Manager) recordSafeError(key string, record domain.OwnershipRecord, reason string) error {
	// The outer snapshot may be stale if another scan or usage transition
	// updated this credential while the Host lock was being acquired. Never
	// overwrite a newer ownership attempt with the old record.
	current, ok := m.store.Get(key)
	if !ok || (record.AttemptID != "" && current.AttemptID != record.AttemptID) {
		return nil
	}
	record = current
	record.LastReason = reason
	m.scheduleBackoff(&record)
	return m.store.Update(func(next *domain.State) error {
		current, ok := next.Credentials[key]
		if !ok || current.AttemptID != record.AttemptID {
			return nil
		}
		next.Credentials[key] = record
		return nil
	})
}

func wipeCredentialJSON(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func newAttemptID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("attempt-%d", time.Now().UnixNano())
	}
	return "attempt-" + hex.EncodeToString(buf)
}
