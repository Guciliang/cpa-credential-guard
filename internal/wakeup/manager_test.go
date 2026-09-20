package wakeup

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"cpa-credential-guard/internal/codexhealth"
	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/state"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type wakeHost struct {
	entry pluginapi.HostAuthFileEntry
	raw   []byte
}

func (h *wakeHost) List(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	return []pluginapi.HostAuthFileEntry{h.entry}, nil
}
func (h *wakeHost) Get(context.Context, string) (pluginapi.HostAuthGetResponse, error) {
	return pluginapi.HostAuthGetResponse{AuthIndex: h.entry.AuthIndex, Name: h.entry.Name, JSON: append([]byte(nil), h.raw...)}, nil
}
func (h *wakeHost) GetRuntime(context.Context, string) (pluginapi.HostAuthGetRuntimeResponse, error) {
	return pluginapi.HostAuthGetRuntimeResponse{Auth: h.entry}, nil
}
func (h *wakeHost) Save(context.Context, pluginapi.HostAuthSaveRequest) (pluginapi.HostAuthSaveResponse, error) {
	return pluginapi.HostAuthSaveResponse{}, errors.New("not used")
}

type wakeClient struct {
	mu     sync.Mutex
	calls  int
	result codexhealth.WakeResult
}

func (c *wakeClient) Wake(context.Context, []byte, string, string) (codexhealth.WakeResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.result.ErrorCode != "" {
		return c.result, nil
	}
	return codexhealth.WakeResult{Completed: true, ErrorCode: "wake_success"}, nil
}
func (c *wakeClient) count() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }

func newWakeFixture(t *testing.T) (*state.Store, *credentials.Repository, *wakeClient, time.Time) {
	t.Helper()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	raw := []byte(`{"type":"codex","access_token":"transient-token","disabled":false}`)
	host := &wakeHost{entry: pluginapi.HostAuthFileEntry{AuthIndex: "a", ID: "id-a", Name: "a.json", Provider: "codex", Type: "codex", Size: int64(len(raw)), ModTime: now, UpdatedAt: now}, raw: raw}
	repo := credentials.NewRepository(host)
	store, _, err := state.NewWithClock(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return store, repo, &wakeClient{}, now
}

func TestNewWithClockPreservesConfiguredScanInterval(t *testing.T) {
	configured := 30 * time.Second
	manager := NewWithClock(nil, nil, nil, Config{ScanInterval: configured}, time.Now)
	if manager.cfg.ScanInterval != configured {
		t.Fatalf("scan interval=%s, want %s", manager.cfg.ScanInterval, configured)
	}
}

func TestInitialWakeIsIdempotentAndSeparateFromNormalUsage(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	manager := NewWithClock(store, repo, client, Config{Enabled: true, InitialEnabled: true, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 1 {
		t.Fatalf("wake calls=%d", got)
	}
	observation, ok := store.GetObservation("codex:a")
	if !ok || observation.InitialWakeup == nil || observation.InitialWakeup.Status != "success" {
		t.Fatalf("observation=%#v ok=%v", observation, ok)
	}
	if observation.Usage != nil {
		t.Fatalf("wakeup incorrectly recorded normal usage: %#v", observation.Usage)
	}
}

func TestResetWakeUsesPersistedOwnershipWindow(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(next *domain.State) error {
		next.Credentials["codex:a"] = domain.OwnershipRecord{
			AuthIndex:                  "a",
			AuthID:                     "id-a",
			FileName:                   "a.json",
			DisabledAt:                 now.Add(-2 * time.Minute),
			WasEnabled:                 true,
			ContentHashWithoutDisabled: snap.ContentHashWithoutDisabled,
			Phase:                      domain.PhaseOwnedDisabled,
			AttemptID:                  "attempt-1",
			ResetAt:                    now.Add(-time.Minute),
			NextCheckAt:                now,
			LastReason:                 "quota_exhausted",
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewWithClock(store, repo, client, Config{Enabled: true, ResetEnabled: true, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 1 {
		t.Fatalf("wake calls=%d, persisted reset window was not used", got)
	}
}

func TestResetWakeDoesNotReuseInitialWakeSuccess(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	resetAt := now.Add(-time.Minute)
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a"] = domain.CredentialObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Quota: &domain.QuotaObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.QuotaExhausted, ResetAt: resetAt, CheckedAt: now}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewWithClock(store, repo, client, Config{Enabled: true, InitialEnabled: true, ResetEnabled: true, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 2 {
		t.Fatalf("wake calls=%d, want separate initial/reset requests", got)
	}
	observation, ok := store.GetObservation("codex:a")
	if !ok || observation.InitialWakeup == nil || observation.ResetWakeup == nil || observation.InitialWakeup.Status != "success" || observation.ResetWakeup.Status != "success" {
		t.Fatalf("observation=%#v ok=%v", observation, ok)
	}
}

func TestResetWakeSkipsWindowAlreadyUsedByNormalCPA(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	resetAt := now.Add(-time.Minute)
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a"] = domain.CredentialObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Quota: &domain.QuotaObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.QuotaAvailable, ResetAt: resetAt, CheckedAt: now}, Usage: &domain.UsageObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Status: "normal_cpa_usage", LastUsedAt: now}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewWithClock(store, repo, client, Config{Enabled: true, ResetEnabled: true, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 0 {
		t.Fatalf("wake calls=%d, normal CPA usage should suppress reset wake", got)
	}
}

func TestStalePendingWakeIsRetriedAfterRequestLease(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a"] = domain.CredentialObservation{
			AuthIndex:     "a",
			IdentityHash:  snap.ContentHashWithoutDisabled,
			InitialWakeup: &domain.WakeupRecord{Mode: domain.WakeupInitial, Status: "pending", IdentityHash: snap.ContentHashWithoutDisabled, AttemptedAt: now.Add(-pendingWakeLease - time.Second), AttemptCount: 1},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewWithClock(store, repo, client, Config{Enabled: true, InitialEnabled: true, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 1 {
		t.Fatalf("wake calls=%d, stale pending request was not retried", got)
	}
}

func TestRetryableWakeHonorsConfiguredBackoff(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	client.result = codexhealth.WakeResult{ErrorCode: "wake_request_failed"}
	clockNow := now
	manager := NewWithClock(store, repo, client, Config{Enabled: true, InitialEnabled: true, InitialBackoff: time.Minute, MaxBackoff: time.Hour, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return clockNow })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	clockNow = now.Add(30 * time.Second)
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 1 {
		t.Fatalf("wake calls=%d before backoff, want 1", got)
	}
	clockNow = now.Add(time.Minute)
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 2 {
		t.Fatalf("wake calls=%d after backoff, want 2", got)
	}
}

func TestResetWakeWindowSummaryCreatesNewGeneration(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	resetAt := now.Add(-time.Minute)
	windows := []domain.QuotaWindow{{Family: "primary", Blocking: true, ResetAt: resetAt}}
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a"] = domain.CredentialObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Quota: &domain.QuotaObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.QuotaExhausted, ResetAt: resetAt, CheckedAt: now, Windows: windows}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewWithClock(store, repo, client, Config{Enabled: true, ResetEnabled: true, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 1 {
		t.Fatalf("first wake calls=%d, want 1", got)
	}
	windows = []domain.QuotaWindow{{Family: "secondary", Blocking: true, ResetAt: resetAt}}
	if err := store.Update(func(next *domain.State) error {
		observation := next.Observations["codex:a"]
		observation.Quota.Windows = windows
		next.Observations["codex:a"] = observation
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 2 {
		t.Fatalf("wake calls=%d after window summary changed, want 2", got)
	}
}

func TestProtocolWakeFailureNeedsManualReviewAndDoesNotRetry(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	client.result = codexhealth.WakeResult{ErrorCode: "wake_protocol_failed"}
	clockNow := now
	manager := NewWithClock(store, repo, client, Config{Enabled: true, InitialEnabled: true, InitialBackoff: time.Minute, MaxBackoff: time.Hour, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return clockNow })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	clockNow = now.Add(2 * time.Hour)
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 1 {
		t.Fatalf("wake calls=%d, protocol failure was retried", got)
	}
	observation, ok := store.GetObservation("codex:a")
	if !ok || observation.InitialWakeup == nil || observation.InitialWakeup.SafeError != "wake_protocol_failed" {
		t.Fatalf("observation=%#v ok=%v", observation, ok)
	}
}

func TestFailedUsageSuppressesInitialWake(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a"] = domain.CredentialObservation{
			AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled,
			Usage: &domain.UsageObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.UsageRequestFailed, LastUsedAt: now},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	manager := NewWithClock(store, repo, client, Config{Enabled: true, InitialEnabled: true, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 0 {
		t.Fatalf("wake calls=%d, failed usage should require review", got)
	}
}

func TestNonRetryableWakeFailureDoesNotRepeatAfterBackoff(t *testing.T) {
	store, repo, client, now := newWakeFixture(t)
	defer store.Close()
	client.result = codexhealth.WakeResult{ErrorCode: "wake_auth_failed"}
	clockNow := now
	manager := NewWithClock(store, repo, client, Config{Enabled: true, InitialEnabled: true, InitialBackoff: time.Minute, MaxBackoff: time.Hour, Model: "gpt-5.6-luna", ReasoningEffort: "low"}, func() time.Time { return clockNow })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	clockNow = now.Add(2 * time.Hour)
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := client.count(); got != 1 {
		t.Fatalf("wake calls=%d, non-retryable failure was retried", got)
	}
}

func TestWakeStateContainsNoCredentialJSON(t *testing.T) {
	store, repo, client, _ := newWakeFixture(t)
	defer store.Close()
	manager := New(store, repo, client, Config{Enabled: true, InitialEnabled: true})
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(store.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || string(raw) == `{"type":"codex"}` {
		t.Fatal("unexpected state")
	}
	if string(raw) == "" || containsAny(string(raw), "transient-token", "Authorization", "Hello") {
		t.Fatalf("state contains secret/request data: %s", raw)
	}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		for i := 0; i+len(needle) <= len(value); i++ {
			if value[i:i+len(needle)] == needle {
				return true
			}
		}
	}
	return false
}
