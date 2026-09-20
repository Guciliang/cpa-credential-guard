package recovery

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/state"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type recoveryHost struct {
	mu          sync.Mutex
	entry       pluginapi.HostAuthFileEntry
	raw         json.RawMessage
	saves       int
	saveStarted chan struct{}
	release     chan struct{}
	runtimeErr  error
}

func newRecoveryHost(raw string) *recoveryHost {
	return &recoveryHost{entry: pluginapi.HostAuthFileEntry{AuthIndex: "a-1", ID: "id-1", Name: "auth.json", Provider: "codex", Type: "codex", Size: int64(len(raw)), ModTime: time.Unix(1, 0)}, raw: json.RawMessage(raw)}
}
func (h *recoveryHost) List(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return []pluginapi.HostAuthFileEntry{h.entry}, nil
}
func (h *recoveryHost) Get(context.Context, string) (pluginapi.HostAuthGetResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return pluginapi.HostAuthGetResponse{AuthIndex: "a-1", Name: h.entry.Name, JSON: append([]byte(nil), h.raw...)}, nil
}
func (h *recoveryHost) GetRuntime(context.Context, string) (pluginapi.HostAuthGetRuntimeResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.runtimeErr != nil {
		return pluginapi.HostAuthGetRuntimeResponse{}, h.runtimeErr
	}
	return pluginapi.HostAuthGetRuntimeResponse{Auth: h.entry}, nil
}
func (h *recoveryHost) Save(_ context.Context, req pluginapi.HostAuthSaveRequest) (pluginapi.HostAuthSaveResponse, error) {
	if h.saveStarted != nil {
		select {
		case h.saveStarted <- struct{}{}:
		default:
		}
		if h.release != nil {
			<-h.release
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.saves++
	h.raw = append([]byte(nil), req.JSON...)
	h.entry.Size = int64(len(h.raw))
	h.entry.ModTime = h.entry.ModTime.Add(time.Second)
	h.entry.UpdatedAt = h.entry.ModTime
	return pluginapi.HostAuthSaveResponse{Name: req.Name}, nil
}

type fakeProber struct {
	mu      sync.Mutex
	calls   int
	summary domain.ProbeSummary
	block   chan struct{}
}

func (p *fakeProber) Probe(ctx context.Context, raw []byte) (domain.ProbeSummary, error) {
	if len(raw) == 0 {
		panic("empty credential")
	}
	p.mu.Lock()
	p.calls++
	summary := p.summary
	block := p.block
	p.mu.Unlock()
	if block != nil {
		select {
		case <-ctx.Done():
			return domain.ProbeSummary{}, ctx.Err()
		case <-block:
		}
	}
	return summary, nil
}

func dueState(t *testing.T, store *state.Store, record domain.OwnershipRecord) {
	t.Helper()
	if err := store.Update(func(next *domain.State) error { next.Credentials["codex:a-1"] = record; return nil }); err != nil {
		t.Fatal(err)
	}
}
func TestNewWithClockPreservesConfiguredScanInterval(t *testing.T) {
	configured := 30 * time.Second
	manager := NewWithClock(nil, nil, nil, Config{ScanInterval: configured}, time.Now)
	if manager.cfg.ScanInterval != configured {
		t.Fatalf("scan interval=%s, want %s", manager.cfg.ScanInterval, configured)
	}
}

func TestRecoverySuccessfulProbeRemovesOwnership(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	raw := `{"access_token":"secret","disabled":true,"proxy_url":"http://proxy.example:8080"}`
	h := newRecoveryHost(raw)
	repo := credentials.NewRepository(h)
	before, err := repo.Snapshot(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision == "" {
		t.Fatal("fixture needs runtime revision")
	}
	dir := t.TempDir()
	store, _, err := state.NewWithClock(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record := domain.OwnershipRecord{AuthIndex: "a-1", AuthID: "id-1", FileName: "auth.json", DisabledAt: now.Add(-time.Hour), WasEnabled: true, ContentHashWithoutDisabled: before.ContentHashWithoutDisabled, PluginSaveHostRevision: before.Revision.String(), Phase: domain.PhaseOwnedDisabled, AttemptID: "attempt-1"}
	dueState(t, store, record)
	prober := &fakeProber{summary: domain.ProbeSummary{Status: domain.ProbeSuccess, At: now}}
	manager := NewWithClock(store, repo, prober, Config{Enabled: true, ProbeEnabled: true, InitialBackoff: time.Minute, MaxBackoff: time.Hour}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get("codex:a-1"); ok {
		t.Fatal("successful probe retained ownership")
	}
	observation, ok := store.GetObservation("codex:a-1")
	if !ok || observation.LastHealthCheck == nil || observation.LastHealthCheck.Status != domain.ProbeSuccess {
		t.Fatalf("successful health check was not retained safely: %#v ok=%v", observation, ok)
	}
	var fields map[string]any
	_ = json.Unmarshal(h.raw, &fields)
	if fields["disabled"] != false {
		t.Fatalf("disabled=%v", fields["disabled"])
	}
	if prober.calls != 1 {
		t.Fatalf("probe calls=%d", prober.calls)
	}
}
func TestRecoveryFailedProbeReDisablesAndBacksOff(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	raw := `{"access_token":"secret","disabled":true}`
	h := newRecoveryHost(raw)
	repo := credentials.NewRepository(h)
	before, _ := repo.Snapshot(context.Background(), "a-1")
	store, _, err := state.NewWithClock(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record := domain.OwnershipRecord{AuthIndex: "a-1", AuthID: "id-1", FileName: "auth.json", WasEnabled: true, ContentHashWithoutDisabled: before.ContentHashWithoutDisabled, PluginSaveHostRevision: before.Revision.String(), Phase: domain.PhaseOwnedDisabled, AttemptID: "attempt-1"}
	dueState(t, store, record)
	prober := &fakeProber{summary: domain.ProbeSummary{Status: domain.ProbeExhausted, SafeError: "quota_exhausted", At: now}}
	manager := NewWithClock(store, repo, prober, Config{Enabled: true, ProbeEnabled: true, InitialBackoff: time.Minute, MaxBackoff: time.Hour}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get("codex:a-1")
	if !ok || got.Phase != domain.PhaseOwnedDisabled || got.BackoffLevel != 1 {
		t.Fatalf("record=%#v ok=%v", got, ok)
	}
	if !got.NextCheckAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("next=%s", got.NextCheckAt)
	}
	var fields map[string]any
	_ = json.Unmarshal(h.raw, &fields)
	if fields["disabled"] != true {
		t.Fatalf("disabled=%v", fields["disabled"])
	}
	if prober.calls != 1 {
		t.Fatalf("calls=%d", prober.calls)
	}
}
func TestRecoveryInterruptedEnableWithoutPostGuardRequiresManualReview(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newRecoveryHost(`{"access_token":"secret","disabled":false}`)
	repo := credentials.NewRepository(h)
	snap, err := repo.Snapshot(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	store, _, err := state.NewWithClock(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record := domain.OwnershipRecord{AuthIndex: "a-1", AuthID: "id-1", FileName: "auth.json", WasEnabled: true, ContentHashWithoutDisabled: snap.ContentHashWithoutDisabled, PluginSaveHostRevision: snap.Revision.String(), Phase: domain.PhaseRestorePending, AttemptID: "attempt-pending"}
	dueState(t, store, record)
	prober := &fakeProber{summary: domain.ProbeSummary{Status: domain.ProbeSuccess, At: now}}
	manager := NewWithClock(store, repo, prober, Config{Enabled: true, ProbeEnabled: true}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get("codex:a-1")
	if !ok || got.Phase != domain.PhaseManualReview {
		t.Fatalf("record=%#v ok=%v", got, ok)
	}
	if prober.calls != 0 || h.saves != 0 {
		t.Fatalf("probe calls=%d saves=%d", prober.calls, h.saves)
	}
}

func TestRecoveryUnavailablePostEnableGuardRequiresManualReview(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newRecoveryHost(`{"access_token":"secret","disabled":false}`)
	repo := credentials.NewRepository(h)
	snap, err := repo.Snapshot(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	h.runtimeErr = errors.New("runtime unavailable")
	store, _, err := state.NewWithClock(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record := domain.OwnershipRecord{AuthIndex: "a-1", AuthID: "id-1", FileName: "auth.json", WasEnabled: true, ContentHashWithoutDisabled: snap.ContentHashWithoutDisabled, PostEnableHashWithoutDisabled: snap.ContentHashWithoutDisabled, PostEnableHostRevision: snap.Revision.String(), Phase: domain.PhaseProbePending, AttemptID: "attempt-pending"}
	dueState(t, store, record)
	prober := &fakeProber{summary: domain.ProbeSummary{Status: domain.ProbeSuccess, At: now}}
	manager := NewWithClock(store, repo, prober, Config{Enabled: true, ProbeEnabled: true}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get("codex:a-1")
	if !ok || got.Phase != domain.PhaseManualReview || got.LastReason != "post_enable_guard_unavailable" {
		t.Fatalf("record=%#v ok=%v", got, ok)
	}
	if prober.calls != 0 || h.saves != 0 {
		t.Fatalf("probe calls=%d saves=%d", prober.calls, h.saves)
	}
}

func TestRecoveryCapsBackoffLevelAtStateLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := newRecoveryHost(`{"access_token":"secret","disabled":true}`)
	repo := credentials.NewRepository(h)
	before, err := repo.Snapshot(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	store, _, err := state.NewWithClock(t.TempDir(), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	record := domain.OwnershipRecord{AuthIndex: "a-1", AuthID: "id-1", FileName: "auth.json", WasEnabled: true, ContentHashWithoutDisabled: before.ContentHashWithoutDisabled, PluginSaveHostRevision: before.Revision.String(), Phase: domain.PhaseOwnedDisabled, AttemptID: "attempt-limit", BackoffLevel: maxRecoveryBackoffLevel}
	dueState(t, store, record)
	manager := NewWithClock(store, repo, &fakeProber{summary: domain.ProbeSummary{Status: domain.ProbeExhausted, SafeError: "quota_exhausted", At: now}}, Config{Enabled: true, ProbeEnabled: true, InitialBackoff: time.Minute, MaxBackoff: time.Hour}, func() time.Time { return now })
	if err := manager.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get("codex:a-1")
	if !ok || got.BackoffLevel != maxRecoveryBackoffLevel {
		t.Fatalf("record=%#v ok=%v", got, ok)
	}
}
