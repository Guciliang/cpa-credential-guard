package app

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"cpa-credential-guard/internal/config"
	"cpa-credential-guard/internal/domain"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type appHost struct {
	mu    sync.Mutex
	entry pluginapi.HostAuthFileEntry
	raw   json.RawMessage
	saves int
}

func newAppHost() *appHost {
	raw := json.RawMessage(`{"type":"codex","access_token":"secret","disabled":false,"priority":4}`)
	return &appHost{entry: pluginapi.HostAuthFileEntry{AuthIndex: "a-1", ID: "id-1", Name: "auth.json", Provider: "codex", Type: "codex", Size: int64(len(raw)), ModTime: time.Unix(1, 0)}, raw: raw}
}
func (h *appHost) List(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return []pluginapi.HostAuthFileEntry{h.entry}, nil
}
func (h *appHost) Get(context.Context, string) (pluginapi.HostAuthGetResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return pluginapi.HostAuthGetResponse{AuthIndex: "a-1", Name: h.entry.Name, JSON: append([]byte(nil), h.raw...)}, nil
}
func (h *appHost) GetRuntime(context.Context, string) (pluginapi.HostAuthGetRuntimeResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return pluginapi.HostAuthGetRuntimeResponse{Auth: h.entry}, nil
}
func (h *appHost) Save(_ context.Context, req pluginapi.HostAuthSaveRequest) (pluginapi.HostAuthSaveResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.raw = append([]byte(nil), req.JSON...)
	h.entry.Size = int64(len(h.raw))
	h.entry.ModTime = h.entry.ModTime.Add(time.Second)
	h.entry.UpdatedAt = h.entry.ModTime
	h.saves++
	return pluginapi.HostAuthSaveResponse{Name: req.Name}, nil
}
func TestProcessUsageDisablesOnlyClassifiedCodexCredential(t *testing.T) {
	h := newAppHost()
	cfg := config.Config{Enabled: true, StateDir: "internal/.test-app-state", ScanInterval: 10 * time.Minute, InitialBackoff: time.Minute, MaxBackoff: time.Hour, ProbeProvider: "codex", ProbeTimeout: time.Second, QuotaDetectionEnabled: true, DetectHTTP429: true, ProxyManagementEnabled: true}
	t.Cleanup(func() { _ = os.RemoveAll(cfg.StateDir) })
	controller, err := New(context.Background(), cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Shutdown()
	record := pluginapi.UsageRecord{Provider: "codex", AuthIndex: "a-1", Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429, Body: `{"error":{"type":"usage_limit_reached"}}`}}
	if err := controller.ProcessUsage(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(h.raw, &fields)
	if fields["disabled"] != true || h.saves != 1 {
		t.Fatalf("fields=%v saves=%d", fields, h.saves)
	}
	bare := pluginapi.UsageRecord{Provider: "codex", AuthIndex: "a-1", Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429, Body: `{"error":{"type":"rate_limit_error"}}`}}
	if err := controller.ProcessUsage(context.Background(), bare); err != nil {
		t.Fatal(err)
	}
	if h.saves != 1 {
		t.Fatalf("bare 429 caused save=%d", h.saves)
	}
}
func TestProcessUsageRecordsNormalCodexUseSeparatelyFromQuotaDetection(t *testing.T) {
	h := newAppHost()
	cfg := config.Config{Enabled: true, StateDir: "internal/.test-app-state-usage", ScanInterval: 10 * time.Minute, InitialBackoff: time.Minute, MaxBackoff: time.Hour, ProbeProvider: "codex", ProbeTimeout: time.Second, QuotaDetectionEnabled: false, DetectHTTP429: true}
	t.Cleanup(func() { _ = os.RemoveAll(cfg.StateDir) })
	controller, err := New(context.Background(), cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Shutdown()
	requestedAt := time.Unix(123, 0).UTC()
	snap, err := controller.repo.Snapshot(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.store.Update(func(next *domain.State) error {
		next.Observations["codex:a-1"] = domain.CredentialObservation{AuthIndex: "a-1", IdentityHash: snap.ContentHashWithoutDisabled, Quota: &domain.QuotaObservation{AuthIndex: "a-1", IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.QuotaExhausted, ResetAt: requestedAt.Add(-time.Hour)}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	record := pluginapi.UsageRecord{Provider: "codex", AuthIndex: "a-1", Generate: true, RequestedAt: requestedAt}
	if err := controller.ProcessUsage(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	observation, ok := controller.store.GetObservation("codex:a-1")
	if !ok || observation.Usage == nil || observation.Usage.Status != "normal_cpa_usage" || !observation.Usage.PostReset || !observation.Usage.LastUsedAt.Equal(requestedAt) {
		t.Fatalf("observation=%#v ok=%v", observation, ok)
	}
	if h.saves != 0 {
		t.Fatalf("normal usage changed Host credential, saves=%d", h.saves)
	}
}

func TestProcessUsageRecordsFailedCodexUseAsUnknown(t *testing.T) {
	h := newAppHost()
	cfg := config.Config{Enabled: true, StateDir: "internal/.test-app-state-failed-usage", ScanInterval: 10 * time.Minute, InitialBackoff: time.Minute, MaxBackoff: time.Hour, ProbeProvider: "codex", ProbeTimeout: time.Second, QuotaDetectionEnabled: false}
	t.Cleanup(func() { _ = os.RemoveAll(cfg.StateDir) })
	controller, err := New(context.Background(), cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Shutdown()
	if err := controller.ProcessUsage(context.Background(), pluginapi.UsageRecord{Provider: "codex", AuthIndex: "a-1", Generate: true, Failed: true, RequestedAt: time.Unix(321, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	observation, ok := controller.store.GetObservation("codex:a-1")
	if !ok || observation.Usage == nil || observation.Usage.Status != domain.UsageRequestFailed {
		t.Fatalf("observation=%#v ok=%v", observation, ok)
	}
	if h.saves != 0 {
		t.Fatalf("failed usage changed Host credential, saves=%d", h.saves)
	}
}

func TestProcessUsageRejectsCodexEventForNonCodexHostEntry(t *testing.T) {
	h := newAppHost()
	h.entry.Provider = "claude"
	h.entry.Type = "claude"
	cfg := config.Config{Enabled: true, StateDir: "internal/.test-app-state-host-provider", ScanInterval: 10 * time.Minute, InitialBackoff: time.Minute, MaxBackoff: time.Hour, ProbeProvider: "codex", ProbeTimeout: time.Second, QuotaDetectionEnabled: true, DetectHTTP429: true}
	t.Cleanup(func() { _ = os.RemoveAll(cfg.StateDir) })
	controller, err := New(context.Background(), cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Shutdown()
	record := pluginapi.UsageRecord{Provider: "codex", AuthIndex: "a-1", Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429, Body: `{"error":{"type":"usage_limit_reached"}}`}}
	if err := controller.ProcessUsage(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if h.saves != 0 {
		t.Fatal("Codex event mutated a non-Codex Host entry")
	}
}

func TestProcessUsageIgnoresNonCodex(t *testing.T) {
	h := newAppHost()
	cfg := config.Config{Enabled: true, StateDir: "internal/.test-app-state-non-codex", ScanInterval: 10 * time.Minute, InitialBackoff: time.Minute, MaxBackoff: time.Hour, ProbeProvider: "codex", ProbeTimeout: time.Second, QuotaDetectionEnabled: true, DetectHTTP429: true}
	t.Cleanup(func() { _ = os.RemoveAll(cfg.StateDir) })
	controller, err := New(context.Background(), cfg, h)
	if err != nil {
		t.Fatal(err)
	}
	defer controller.Shutdown()
	record := pluginapi.UsageRecord{Provider: "claude", AuthIndex: "a-1", Failed: true, Failure: pluginapi.UsageFailure{StatusCode: 429, Body: `{"error":{"type":"usage_limit_reached"}}`}}
	if err := controller.ProcessUsage(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if h.saves != 0 {
		t.Fatal("non-Codex credential mutated")
	}
}
