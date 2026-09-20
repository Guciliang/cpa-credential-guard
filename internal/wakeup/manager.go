// Package wakeup owns Credential Guard's explicit, real Codex wake requests.
// It is intentionally separate from quota health probing and normal CPA usage.
package wakeup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"cpa-credential-guard/internal/codexhealth"
	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/state"
)

const (
	maxAttempts      = 3
	pendingWakeLease = 2 * time.Minute
)

type Client interface {
	Wake(context.Context, []byte, string, string) (codexhealth.WakeResult, error)
}

type Config struct {
	Enabled         bool
	InitialEnabled  bool
	ResetEnabled    bool
	ScanInterval    time.Duration
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	Model           string
	ReasoningEffort string
}

type Manager struct {
	store  *state.Store
	repo   *credentials.Repository
	client Client
	cfg    Config
	now    func() time.Time
	mu     sync.Mutex
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(store *state.Store, repo *credentials.Repository, client Client, cfg Config) *Manager {
	return NewWithClock(store, repo, client, cfg, time.Now)
}

func NewWithClock(store *state.Store, repo *credentials.Repository, client Client, cfg Config, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = 15 * time.Minute
	}
	if cfg.MaxBackoff < cfg.InitialBackoff {
		cfg.MaxBackoff = cfg.InitialBackoff
	}
	cfg.Model = strings.TrimSpace(cfg.Model)
	if cfg.Model == "" {
		cfg.Model = codexhealth.WakeModel
	}
	cfg.ReasoningEffort = strings.ToLower(strings.TrimSpace(cfg.ReasoningEffort))
	if cfg.ReasoningEffort == "" {
		cfg.ReasoningEffort = "low"
	}
	return &Manager{store: store, repo: repo, client: client, cfg: cfg, now: now}
}

func (m *Manager) Enabled() bool {
	return m != nil && m.cfg.Enabled && m.store != nil && m.repo != nil && m.client != nil && (m.cfg.InitialEnabled || m.cfg.ResetEnabled)
}

func (m *Manager) Start(parent context.Context) {
	if m == nil {
		return
	}
	if parent == nil {
		parent = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil || !m.Enabled() || m.cfg.ScanInterval <= 0 {
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
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel != nil {
		cancel()
		m.wg.Wait()
	}
}

func (m *Manager) Scan(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if m == nil || !m.Enabled() {
		return nil
	}
	entries, err := m.repo.List(ctx)
	if err != nil {
		return err
	}
	type candidate struct {
		index    string
		provider string
		typ      string
	}
	candidates := make([]candidate, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if strings.EqualFold(strings.TrimSpace(entry.Provider), "codex") || strings.EqualFold(strings.TrimSpace(entry.Type), "codex") {
			index := strings.TrimSpace(entry.AuthIndex)
			if index == "" {
				continue
			}
			// A malformed or duplicate Host listing must not cause two real
			// wake requests in one scan. Keep the first deterministic identity
			// and process each auth index at most once.
			if _, exists := seen[index]; exists {
				continue
			}
			seen[index] = struct{}{}
			candidates = append(candidates, candidate{index: index, provider: entry.Provider, typ: entry.Type})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].index < candidates[j].index })
	var scanErr error
	for _, candidate := range candidates {
		if err := m.repo.WithLock(ctx, candidate.index, func() error { return m.processLocked(ctx, candidate.index) }); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if scanErr == nil {
				scanErr = err
			}
		}
	}
	return scanErr
}

func (m *Manager) processLocked(ctx context.Context, authIndex string) error {
	snap, err := m.repo.Snapshot(ctx, authIndex)
	if err != nil {
		return err
	}
	defer wipeBytes(snap.JSON)
	if !snap.RuntimeOK || snap.ContentHashWithoutDisabled == "" {
		return nil
	}
	observation, _ := m.store.GetObservation("codex:" + authIndex)
	if observation.AuthIndex == "" {
		observation.AuthIndex = authIndex
	}
	if observation.IdentityHash != "" && observation.IdentityHash != snap.ContentHashWithoutDisabled {
		observation = domain.CredentialObservation{AuthIndex: authIndex, IdentityHash: snap.ContentHashWithoutDisabled}
	} else {
		observation.IdentityHash = snap.ContentHashWithoutDisabled
	}
	// A quota-exhaustion ownership record predates the optional observation
	// record in some state files. Preserve its identity-bound reset window so a
	// post-reset wake can still run after a restart, including while recovery
	// has the credential disabled. A health probe remains read-only; it is only
	// used here as persisted window metadata, never as use evidence.
	if observation.Quota == nil {
		if record, ok := m.store.Get("codex:" + authIndex); ok {
			observation.Quota = persistedResetQuota(record, snap.ContentHashWithoutDisabled)
		}
	}
	if !snap.Disabled && m.cfg.InitialEnabled && eligibleInitial(observation, snap.ContentHashWithoutDisabled, m.now()) {
		if err := m.runWakeLocked(ctx, authIndex, snap.JSON, &observation, domain.WakeupInitial, ""); err != nil {
			return err
		}
		// runWakeLocked clears the snapshot bytes immediately after the one
		// token-bearing request. If both independent wake switches happen to be
		// eligible in one scan, obtain a fresh snapshot before the second request
		// rather than reusing a wiped or stale credential payload.
		if m.cfg.ResetEnabled && eligibleReset(observation, snap.ContentHashWithoutDisabled, m.now()) {
			fresh, snapshotErr := m.repo.Snapshot(ctx, authIndex)
			if snapshotErr != nil {
				return snapshotErr
			}
			if !fresh.RuntimeOK || fresh.ContentHashWithoutDisabled != snap.ContentHashWithoutDisabled {
				wipeBytes(fresh.JSON)
				return nil
			}
			defer wipeBytes(fresh.JSON)
			snap = fresh
		}
	}
	if m.cfg.ResetEnabled && eligibleReset(observation, snap.ContentHashWithoutDisabled, m.now()) {
		windowKey := resetWindowKey(observation.IdentityHash, observation.Quota.ResetAt, observation.Quota.Windows)
		if err := m.runWakeLocked(ctx, authIndex, snap.JSON, &observation, domain.WakeupReset, windowKey); err != nil {
			return err
		}
	}
	return nil
}

func eligibleInitial(observation domain.CredentialObservation, identity string, now time.Time) bool {
	if observation.IdentityHash != identity {
		return false
	}
	if observation.Usage != nil && observation.Usage.IdentityHash == identity {
		switch observation.Usage.Status {
		case domain.UsageNormal:
			return false
		case domain.UsageRequestFailed, domain.UsageUnknown, "unknown":
			// A failed or ambiguous CPA request is not proof that no request
			// consumed quota. Require human review or a new credential identity
			// instead of immediately issuing another real request.
			return false
		}
	}
	wake := observation.InitialWakeup
	if wake == nil {
		return true
	}
	if wake.IdentityHash != identity {
		return true
	}
	if wake.Status == "success" {
		return false
	}
	if wake.Status == "unknown" {
		return false
	}
	if wake.Status == "pending" {
		if wake.AttemptCount >= maxAttempts || (!wake.AttemptedAt.IsZero() && now.Before(wake.AttemptedAt.Add(pendingWakeLease))) {
			return false
		}
	}
	if wake.Status == "failed" && !retryable(wake.SafeError) {
		return false
	}
	return wake.AttemptCount < maxAttempts && (wake.NextAttemptAt.IsZero() || !now.Before(wake.NextAttemptAt))
}

func persistedResetQuota(record domain.OwnershipRecord, identity string) *domain.QuotaObservation {
	if record.ContentHashWithoutDisabled != identity {
		return nil
	}
	if record.Phase == domain.PhaseManualReview {
		return nil
	}
	resetAt := record.ResetAt
	if resetAt.IsZero() && record.LastProbe != nil {
		for _, window := range record.LastProbe.Windows {
			if window.Blocking && !window.ResetAt.IsZero() && (resetAt.IsZero() || window.ResetAt.After(resetAt)) {
				resetAt = window.ResetAt
			}
		}
	}
	if resetAt.IsZero() {
		return nil
	}
	checkedAt := record.DisabledAt
	if record.LastProbe != nil && !record.LastProbe.At.IsZero() {
		checkedAt = record.LastProbe.At
	}
	observation := &domain.QuotaObservation{
		AuthIndex:    record.AuthIndex,
		IdentityHash: identity,
		Status:       domain.QuotaExhausted,
		ResetAt:      resetAt,
		CheckedAt:    checkedAt,
	}
	if record.LastProbe != nil {
		observation.Windows = domain.SafeQuotaWindows(record.LastProbe.Windows)
	}
	return observation
}

func eligibleReset(observation domain.CredentialObservation, identity string, now time.Time) bool {
	// A reset timestamp on an available or unknown observation is not evidence
	// of a blocking quota window. Requiring the exhausted status prevents a
	// non-blocking informational window from becoming a consuming wake trigger
	// merely because its timestamp later expires.
	if observation.IdentityHash != identity || observation.Quota == nil || observation.Quota.IdentityHash != identity || observation.Quota.Status != domain.QuotaExhausted || observation.Quota.ResetAt.IsZero() || now.Before(observation.Quota.ResetAt) {
		return false
	}
	// A normal CPA request after the observed reset is already real Codex use;
	// the plugin must not send a second, consuming wake request for that window.
	if observation.Usage != nil && observation.Usage.IdentityHash == identity && !observation.Usage.LastUsedAt.IsZero() && !observation.Usage.LastUsedAt.Before(observation.Quota.ResetAt) {
		switch observation.Usage.Status {
		case domain.UsageNormal, domain.UsageRequestFailed, domain.UsageUnknown, "unknown":
			// A failed or ambiguous request after reset may already have
			// consumed quota; do not add another request automatically.
			return false
		}
	}
	wake := observation.ResetWakeup
	key := resetWindowKey(identity, observation.Quota.ResetAt, observation.Quota.Windows)
	if wake == nil {
		return true
	}
	if wake.IdentityHash != identity || wake.WindowKey != key {
		// Releases before the window summary was included in the generation
		// key used identity+reset time. A previously completed legacy window
		// must remain idempotent after upgrade; failed legacy attempts may be
		// retried under the stronger key.
		if wake.Status == "success" && wake.IdentityHash == identity && wake.WindowKey == legacyResetWindowKey(identity, observation.Quota.ResetAt) {
			return false
		}
		return true
	}
	if wake.Status == "success" {
		return false
	}
	if wake.Status == "unknown" {
		return false
	}
	if wake.Status == "pending" {
		if wake.AttemptCount >= maxAttempts || (!wake.AttemptedAt.IsZero() && now.Before(wake.AttemptedAt.Add(pendingWakeLease))) {
			return false
		}
	}
	if wake.Status == "failed" && !retryable(wake.SafeError) {
		return false
	}
	return wake.AttemptCount < maxAttempts && (wake.NextAttemptAt.IsZero() || !now.Before(wake.NextAttemptAt))
}

func resetWindowKey(identity string, resetAt time.Time, windows []domain.QuotaWindow) string {
	// Window order can come from a JSON object and is therefore not stable.
	// Sort a sanitized copy before hashing so equivalent observations produce
	// the same generation while a changed window summary creates a new one.
	safeWindows := domain.SafeQuotaWindows(windows)
	sort.SliceStable(safeWindows, func(i, j int) bool {
		left, right := safeWindows[i], safeWindows[j]
		if left.Family != right.Family {
			return left.Family < right.Family
		}
		if !left.ResetAt.Equal(right.ResetAt) {
			return left.ResetAt.Before(right.ResetAt)
		}
		if left.WindowSeconds != right.WindowSeconds {
			return left.WindowSeconds < right.WindowSeconds
		}
		if left.LimitReached != right.LimitReached {
			return !left.LimitReached
		}
		if left.Blocking != right.Blocking {
			return !left.Blocking
		}
		return quotaWindowValueKey(left) < quotaWindowValueKey(right)
	})
	encoded, _ := json.Marshal(safeWindows)
	digest := sha256.Sum256(encoded)
	return identity + "|" + resetAt.UTC().Format(time.RFC3339Nano) + "|" + hex.EncodeToString(digest[:])
}

func quotaWindowValueKey(window domain.QuotaWindow) string {
	encoded, _ := json.Marshal(window)
	return string(encoded)
}

func legacyResetWindowKey(identity string, resetAt time.Time) string {
	return identity + "|" + resetAt.UTC().Format(time.RFC3339Nano)
}

func (m *Manager) runWakeLocked(ctx context.Context, authIndex string, raw []byte, observation *domain.CredentialObservation, mode, windowKey string) error {
	if observation == nil {
		wipeBytes(raw)
		return nil
	}
	// The caller owns the snapshot buffer. Clear it as soon as this single
	// token-bearing request path returns, including setup/persistence failures.
	defer wipeBytes(raw)
	now := m.now().UTC()
	var current *domain.WakeupRecord
	if mode == domain.WakeupInitial {
		current = observation.InitialWakeup
	} else {
		current = observation.ResetWakeup
	}
	record := domain.WakeupRecord{Mode: mode, Status: "pending", IdentityHash: observation.IdentityHash, WindowKey: windowKey, AttemptedAt: now, AttemptCount: 1}
	if current != nil {
		record = *current
		record.Mode = mode
		record.Status = "pending"
		record.IdentityHash = observation.IdentityHash
		record.WindowKey = windowKey
		record.AttemptedAt = now
		record.AttemptCount++
		record.SafeError = ""
		record.NextAttemptAt = time.Time{}
	}
	if err := m.saveWakeObservation(authIndex, observation, &record, mode); err != nil {
		return err
	}
	var result codexhealth.WakeResult
	var err error
	if m.client == nil {
		result.ErrorCode = "health_client_unavailable"
	} else {
		result, err = m.client.Wake(ctx, raw, m.cfg.Model, m.cfg.ReasoningEffort)
	}
	if err != nil {
		result.ErrorCode = "wake_request_failed"
	}
	if result.Completed && result.ErrorCode == "wake_success" {
		record.Status = "success"
		record.CompletedAt = m.now().UTC()
		record.SafeError = "wake_success"
		record.NextAttemptAt = time.Time{}
	} else {
		record.Status = "failed"
		if result.ErrorCode == "" {
			result.ErrorCode = "wake_manual_review"
		}
		record.SafeError = result.ErrorCode
		if retryable(result.ErrorCode) && record.AttemptCount < maxAttempts {
			record.NextAttemptAt = m.now().UTC().Add(m.backoff(record.AttemptCount))
		} else {
			record.NextAttemptAt = time.Time{}
		}
	}
	return m.saveWakeObservation(authIndex, observation, &record, mode)
}

func retryable(code string) bool {
	switch code {
	case "timeout", "wake_request_failed", "connection_failed", "canceled":
		return true
	default:
		return false
	}
}

func (m *Manager) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := m.cfg.InitialBackoff
	for i := 1; i < attempt; i++ {
		if delay >= m.cfg.MaxBackoff/2 {
			return m.cfg.MaxBackoff
		}
		delay *= 2
	}
	if delay > m.cfg.MaxBackoff {
		return m.cfg.MaxBackoff
	}
	return delay
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (m *Manager) saveWakeObservation(authIndex string, observation *domain.CredentialObservation, record *domain.WakeupRecord, mode string) error {
	return m.store.Update(func(next *domain.State) error {
		if next.Observations == nil {
			next.Observations = map[string]domain.CredentialObservation{}
		}
		key := "codex:" + authIndex
		current := next.Observations[key]
		if current.IdentityHash != "" && current.IdentityHash != observation.IdentityHash {
			current = domain.CredentialObservation{}
		}
		current.AuthIndex = authIndex
		current.IdentityHash = observation.IdentityHash
		if current.Quota == nil {
			current.Quota = observation.Quota
		}
		if current.Usage == nil {
			current.Usage = observation.Usage
		}
		if mode == domain.WakeupInitial {
			current.InitialWakeup = record
		} else {
			current.ResetWakeup = record
		}
		next.Observations[key] = current
		return nil
	})
}
