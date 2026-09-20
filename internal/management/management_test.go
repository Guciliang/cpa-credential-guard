package management

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"cpa-credential-guard/internal/codexhealth"
	"cpa-credential-guard/internal/config"
	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/proxy"
	"cpa-credential-guard/internal/state"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type managementHost struct {
	mu      sync.Mutex
	entries map[string]pluginapi.HostAuthFileEntry
	raw     map[string]json.RawMessage
	fail    map[string]bool
	saves   []pluginapi.HostAuthSaveRequest
}

func newManagementHost() *managementHost {
	h := &managementHost{entries: map[string]pluginapi.HostAuthFileEntry{}, raw: map[string]json.RawMessage{}, fail: map[string]bool{}}
	for i := 1; i <= 3; i++ {
		idx := string(rune('a' + i - 1))
		raw := `{"type":"codex","access_token":"secret-` + idx + `","disabled":false,"proxy_url":"http://old.example:8080","priority":7}`
		h.entries[idx] = pluginapi.HostAuthFileEntry{AuthIndex: idx, ID: "id-" + idx, Name: idx + `.json`, Provider: "codex", Type: "codex", Size: int64(len(raw)), ModTime: time.Unix(int64(i), 0)}
		h.raw[idx] = json.RawMessage(raw)
	}
	h.fail["b"] = true
	return h
}
func (h *managementHost) List(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]pluginapi.HostAuthFileEntry, 0, len(h.entries))
	for _, e := range h.entries {
		out = append(out, e)
	}
	return out, nil
}
func (h *managementHost) Get(_ context.Context, index string) (pluginapi.HostAuthGetResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.entries[index]
	if !ok {
		return pluginapi.HostAuthGetResponse{}, errors.New("missing")
	}
	return pluginapi.HostAuthGetResponse{AuthIndex: index, Name: e.Name, JSON: append([]byte(nil), h.raw[index]...)}, nil
}
func (h *managementHost) GetRuntime(_ context.Context, index string) (pluginapi.HostAuthGetRuntimeResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.entries[index]
	if !ok {
		return pluginapi.HostAuthGetRuntimeResponse{}, errors.New("missing")
	}
	return pluginapi.HostAuthGetRuntimeResponse{Auth: e}, nil
}
func (h *managementHost) Save(_ context.Context, req pluginapi.HostAuthSaveRequest) (pluginapi.HostAuthSaveResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for idx, e := range h.entries {
		if e.Name == req.Name {
			if h.fail[idx] {
				return pluginapi.HostAuthSaveResponse{}, errors.New("save failed")
			}
			h.raw[idx] = append([]byte(nil), req.JSON...)
			e.Size = int64(len(req.JSON))
			e.ModTime = e.ModTime.Add(time.Second)
			e.UpdatedAt = e.ModTime
			h.entries[idx] = e
			h.saves = append(h.saves, req)
			return pluginapi.HostAuthSaveResponse{Name: req.Name}, nil
		}
	}
	return pluginapi.HostAuthSaveResponse{}, errors.New("missing")
}

type managementRoundTripFunc func(*http.Request) (*http.Response, error)

func (f managementRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestRegistrationUsesPluginScopedRoutes(t *testing.T) {
	svc := New(config.Config{}, nil, nil, nil)
	registered, err := svc.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{BasePath: "/v0/management"})
	if err != nil {
		t.Fatal(err)
	}
	if len(registered.Routes) != 9 || registered.Routes[0].Path != "/plugins/cpa-credential-guard/status" {
		t.Fatalf("routes=%#v", registered.Routes)
	}
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/v0/management/plugins/cpa-credential-guard/status"})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", resp.StatusCode, err, resp.Body)
	}
}

func TestProxyTestReturnsFixedMultiTargetSafeResults(t *testing.T) {
	checker := &proxy.Checker{Timeout: time.Second, RoundTripper: managementRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			t.Fatal("proxy check attached credential headers")
		}
		status := http.StatusNoContent
		if req.URL.Host == "api.openai.com" || req.URL.Host == "api.x.ai" {
			status = http.StatusUnauthorized
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(newManagementHost()), nil, nil)
	svc.SetChecker(checker)
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/test", Body: []byte(`{"proxies":["http://proxy.example:8080"]}`)})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d err=%v body=%s", resp.StatusCode, err, resp.Body)
	}
	var result struct {
		Items   []domain.ProxyTestItem  `json:"items"`
		Summary domain.ProxyTestSummary `json:"summary"`
	}
	if err := json.Unmarshal(resp.Body, &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Items) != 5 || result.Summary.Total != 5 || result.Summary.Passed != 5 {
		t.Fatalf("result=%#v", result)
	}
	expectedTargets := []string{"base_connectivity", "openai", "anthropic", "gemini", "grok"}
	for index, item := range result.Items {
		if item.Target != expectedTargets[index] {
			t.Fatalf("target order=%#v", result.Items)
		}
	}
	if strings.Contains(string(resp.Body), "user:pass") || strings.Contains(string(resp.Body), "Authorization") {
		t.Fatalf("unsafe proxy result=%s", resp.Body)
	}
}

func TestManualQuotaQueryIsExplicitAndStoresSafeProjection(t *testing.T) {
	h := newManagementHost()
	store, _, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var callsMu sync.Mutex
	calls := 0
	client := codexhealth.NewClient()
	callCount := func() int { callsMu.Lock(); defer callsMu.Unlock(); return calls }
	client.RoundTripper = managementRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		if req.URL.String() != codexhealth.UsageURL {
			t.Fatalf("url=%s", req.URL)
		}
		if req.Header.Get("Authorization") == "" || req.Header.Get("Cookie") != "" {
			t.Fatalf("unsafe headers")
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"status_code":200,"body":{"rate_limit":{"primary_window":{"used_percent":20}}}}`))}, nil
	})
	svc := New(config.Config{Enabled: true, ProbeEnabled: true, StateDir: t.TempDir()}, credentials.NewRepository(h), store, nil)
	svc.SetQuotaClient(client)
	if _, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/status"}); err != nil {
		t.Fatal(err)
	}
	if callCount() != 0 {
		t.Fatalf("status unexpectedly queried quota: %d", callCount())
	}
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/quota/query", Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
	var all struct {
		Items []quotaQueryItem `json:"items"`
	}
	if err := json.Unmarshal(resp.Body, &all); err != nil {
		t.Fatal(err)
	}
	if len(all.Items) != 3 || callCount() != 3 {
		t.Fatalf("items=%#v calls=%d", all.Items, callCount())
	}
	for _, item := range all.Items {
		if item.Status != domain.QuotaAvailable {
			t.Fatalf("item=%#v", item)
		}
	}
	if observation, ok := store.GetObservation("codex:a"); !ok || observation.Quota == nil || observation.Quota.Status != domain.QuotaAvailable {
		t.Fatalf("observation=%#v ok=%v", observation, ok)
	}
	resp, err = svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/quota/query", Body: []byte(`{"auth_index":"a"}`)})
	if err != nil || resp.StatusCode != http.StatusOK || callCount() != 4 {
		t.Fatalf("single status=%d err=%v calls=%d", resp.StatusCode, err, callCount())
	}
}

func TestQuotaQueryDisabledDoesNotReadHost(t *testing.T) {
	h := newManagementHost()
	store, _, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	svc := New(config.Config{Enabled: true, ProbeEnabled: false}, credentials.NewRepository(h), store, nil)
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/quota/query", Body: []byte(`{}`)})
	if err != nil || resp.StatusCode != http.StatusOK || !strings.Contains(string(resp.Body), "quota_probe_disabled") {
		t.Fatalf("status=%d err=%v body=%s", resp.StatusCode, err, resp.Body)
	}
}

func TestManagementServesStaticResourceThroughDynamicPath(t *testing.T) {
	svc := New(config.Config{}, nil, nil, nil)
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   "/v0/resource/plugins/cpa-credential-guard/index.html",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if got := resp.Headers.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Fatalf("content type=%q", got)
	}
	body := string(resp.Body)
	if !strings.Contains(body, "CPA 凭证守护") {
		t.Fatalf("resource body does not contain the plugin title")
	}
	for _, marker := range []string{"lang=\"zh-CN\"", "color-scheme: dark", "代理管理", "代理板块", "代理名称", "保存代理名称", "选择代理", "未关联名称", "selection-summary", "proxyTestState", "proxySafeMessage", "probe_enabled", "请先选择凭证", "data-config-key", "type=\"checkbox\"", "PATCH", "应用预览", "测试代理", "连接 CPA", "CPA 管理密钥", "manual-key", "clear-manual", "credentials = 'omit'", "AbortController", "check-target", "跳到主要内容", "pagehide", "invalidatePlan", "previewVersion", "statusProjection", "proxy_profiles", "profile_id", "cli-proxy-auth", "enc::v1::", "cli-proxy-api-webui::secure-storage", "Authorization", "management_key_required", "记住密码", "prefers-reduced-motion", "proxy-test-dialog", "代理是否通过", "query-all-quota", "queryQuota", "quotaRequestGeneration", "quota_probe_disabled", "page-size", "全选当前页", "table-wrap", "credentials-table", "<thead>", "<tbody id=\"credentials\">", "scope=\"col\"", "data-credential-row", "查询额度", "toast-region", "preview-dialog", "data-edit-profile", "cancel-profile-edit", "initial_wakeup_enabled", "reset_wakeup_enabled", "wakeup_model", "wakeup_reasoning_effort", "health_check", "base_connectivity", "target_unexpected_status", "wake_auth_failed", "wake_quota_exhausted", "fallback_mode", "fallback_profile_id", "fallback_state", "需要重新认证", "额度不足：等待额度窗口或手动查询"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("resource body missing Chinese/dark UI marker %q", marker)
		}
	}
	for _, forbidden := range []string{"lang=\"en\"", "color-scheme: light", "color-scheme: light dark", "light-theme", "theme-toggle", "fingerprint", "Fingerprint", "指纹", "批量代理管理", "target_url", "custom_target", "credential-card", "grid-auto-flow", "credentials-board", "代理备注", "选择代理备注", "共享代理备注", "未命名代理", "健康检查不等于实际使用", "text(item.message)"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("resource body contains forbidden light/English theme marker %q", forbidden)
		}
	}
}

func TestStaticResourceKeepsManualKeyMemoryOnly(t *testing.T) {
	body := string(staticIndex)
	for _, forbidden := range []string{"localStorage.setItem", "sessionStorage", "document.cookie", "manualAuthStorage"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("static resource contains manual credential persistence marker %q", forbidden)
		}
	}
	for _, required := range []string{"state.manualAuth = {", "requestOptions.credentials = 'omit'", "headers.set('Authorization'", "state.manualAuth = null", "requestController", "sessionRequestVersion", "busyKind", "resetManualKeyInput", "input.type = 'password'", `id="manual-key" name="management-key" type="password" autocomplete="current-password"`} {
		if !strings.Contains(body, required) {
			t.Fatalf("static resource missing manual credential boundary %q", required)
		}
	}
}

func TestStaticResourceCopiesStayInSync(t *testing.T) {
	rootPage, errRead := os.ReadFile("../../web/index.html")
	if errRead != nil {
		t.Fatal(errRead)
	}
	if !bytes.Equal(rootPage, staticIndex) {
		t.Fatal("root web/index.html differs from the embedded management resource")
	}
}

func TestManagementRejectsNonJSONMutationContentType(t *testing.T) {
	h := newManagementHost()
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{
		Method:  http.MethodPost,
		Path:    "/v0/management/plugins/cpa-credential-guard/proxy/test",
		Headers: http.Header{"Content-Type": []string{"text/plain"}},
		Body:    []byte(`{"proxies":["http://proxy.example:8080"]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
}

func TestPreviewRejectsAmbiguousHostAuthIndex(t *testing.T) {
	h := newManagementHost()
	h.entries["duplicate"] = pluginapi.HostAuthFileEntry{AuthIndex: "a", ID: "id-duplicate", Name: "duplicate.json", Provider: "codex", Type: "codex"}
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	proxyURL := "http://new.example:8080"
	body, _ := json.Marshal(ProxyPreviewRequest{Changes: []ProxyChange{{AuthIndex: "a", ProxyURL: &proxyURL}}})
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(resp.Body), `"error_code":"duplicate_auth_index"`) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
}

func TestStatusRedactsCredentialAndProxySecrets(t *testing.T) {
	h := newManagementHost()
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/status"})
	if err != nil {
		t.Fatal(err)
	}
	body := string(resp.Body)
	for _, secret := range []string{"secret-a", "access_token"} {
		if strings.Contains(body, secret) {
			t.Fatalf("status leaked %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, "proxy.example") && !strings.Contains(body, "old.example") {
		t.Fatalf("status missing redacted endpoint: %s", body)
	}
}
func TestStatusPrefersCurrentManualQuotaAndRejectsStaleIdentity(t *testing.T) {
	h := newManagementHost()
	store, _, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	repo := credentials.NewRepository(h)
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(next *domain.State) error {
		next.Credentials["codex:a"] = domain.OwnershipRecord{
			AuthIndex: "a", AuthID: "id-a", FileName: snap.Name, DisabledAt: time.Unix(10, 0).UTC(),
			WasEnabled: true, ContentHashWithoutDisabled: snap.ContentHashWithoutDisabled,
			Phase: domain.PhaseOwnedDisabled, AttemptID: "attempt-a", LastReason: "quota_exhausted",
			Quota: &domain.QuotaObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.QuotaAvailable},
		}
		next.Observations["codex:a"] = domain.CredentialObservation{
			AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled,
			Quota: &domain.QuotaObservation{AuthIndex: "a", IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.QuotaExhausted, SafeError: "quota_exhausted"},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc := New(config.Config{Enabled: true}, repo, store, nil)
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/status"})
	if err != nil {
		t.Fatal(err)
	}
	var projected statusResponse
	if err := json.Unmarshal(resp.Body, &projected); err != nil {
		t.Fatal(err)
	}
	var row *domain.CredentialProjection
	for index := range projected.Credentials {
		if projected.Credentials[index].AuthIndex == "a" {
			row = &projected.Credentials[index]
			break
		}
	}
	if row == nil || row.Quota == nil || row.Quota.Status != domain.QuotaExhausted {
		t.Fatalf("manual observation did not win: %#v", row)
	}

	h.mu.Lock()
	h.raw["a"] = json.RawMessage(`{"type":"codex","access_token":"replaced-secret","disabled":false,"changed":true}`)
	h.mu.Unlock()
	resp, err = svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/status"})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(resp.Body, &projected); err != nil {
		t.Fatal(err)
	}
	row = nil
	for index := range projected.Credentials {
		if projected.Credentials[index].AuthIndex == "a" {
			row = &projected.Credentials[index]
			break
		}
	}
	if row == nil || row.Quota == nil || row.Quota.Status != domain.QuotaUnknown {
		t.Fatalf("stale identity was not reduced to unknown: %#v", row)
	}
}

func TestStatusProjectionOmitsQuotaAndWakePersistenceHashes(t *testing.T) {
	h := newManagementHost()
	store, _, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a"] = domain.CredentialObservation{AuthIndex: "a", IdentityHash: "private-content-hash", Quota: &domain.QuotaObservation{AuthIndex: "a", IdentityHash: "private-content-hash", Status: domain.QuotaAvailable}, InitialWakeup: &domain.WakeupRecord{Mode: domain.WakeupInitial, Status: "success", IdentityHash: "private-content-hash", WindowKey: "private-window-key", SafeError: "wake_success"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	repo := credentials.NewRepository(h)
	snap, err := repo.Snapshot(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(next *domain.State) error {
		observation := next.Observations["codex:a"]
		observation.IdentityHash = snap.ContentHashWithoutDisabled
		observation.Quota.IdentityHash = snap.ContentHashWithoutDisabled
		observation.InitialWakeup.IdentityHash = snap.ContentHashWithoutDisabled
		next.Observations["codex:a"] = observation
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	svc := New(config.Config{Enabled: true}, repo, store, nil)
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/status"})
	if err != nil {
		t.Fatal(err)
	}
	body := string(resp.Body)
	for _, secret := range []string{"private-content-hash", "private-window-key", "identity_hash", "window_key"} {
		if strings.Contains(body, secret) {
			t.Fatalf("status leaked persistence-only field %q: %s", secret, body)
		}
	}
	if !strings.Contains(body, "wake_success") || !strings.Contains(body, "available") {
		t.Fatalf("status omitted safe projection: %s", body)
	}
}

func TestPreviewApplyHeterogeneousBatchContinuesAfterFailure(t *testing.T) {
	h := newManagementHost()
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	one := "http://one.example:8080"
	two := "socks5://user:pass@two.example:1080"
	raw, _ := json.Marshal(ProxyPreviewRequest{Changes: []ProxyChange{{AuthIndex: "a", ProxyURL: &one}, {AuthIndex: "b", ProxyURL: &two}, {AuthIndex: "c", Clear: true}}})
	preview, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: raw})
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		PlanID string           `json:"plan_id"`
		Items  []map[string]any `json:"items"`
	}
	_ = json.Unmarshal(preview.Body, &p)
	if p.PlanID == "" || len(p.Items) != 3 {
		t.Fatalf("preview=%s", preview.Body)
	}
	previewText := string(preview.Body)
	for _, secret := range []string{"user:pass", "access_token"} {
		if strings.Contains(previewText, secret) {
			t.Fatalf("preview leaked %q", secret)
		}
	}
	applyRaw, _ := json.Marshal(proxyApplyRequest{PlanID: p.PlanID})
	apply, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/apply", Body: applyRaw})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Items []domainResult `json:"items"`
	}
	_ = json.Unmarshal(apply.Body, &result)
	if len(result.Items) != 3 {
		t.Fatalf("apply=%s", apply.Body)
	}
	if result.Items[0].ErrorCode != "" || !result.Items[0].OK {
		t.Fatalf("first=%#v", result.Items[0])
	}
	if result.Items[1].ErrorCode == "" || result.Items[2].ErrorCode != "" || !result.Items[2].OK {
		t.Fatalf("results=%#v", result.Items)
	}
	if len(h.saves) != 2 {
		t.Fatalf("saves=%d", len(h.saves))
	}
}

type domainResult struct {
	AuthIndex string `json:"auth_index"`
	OK        bool   `json:"ok"`
	ErrorCode string `json:"error_code"`
}

func TestStalePreviewIsRejectedWithoutSaving(t *testing.T) {
	h := newManagementHost()
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	proxyURL := "http://new.example:8080"
	body, _ := json.Marshal(ProxyPreviewRequest{Changes: []ProxyChange{{AuthIndex: "a", ProxyURL: &proxyURL}}})
	preview, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	var prepared struct {
		PlanID string `json:"plan_id"`
	}
	if err := json.Unmarshal(preview.Body, &prepared); err != nil || prepared.PlanID == "" {
		t.Fatalf("preview=%s err=%v", preview.Body, err)
	}
	h.mu.Lock()
	h.raw["a"] = json.RawMessage(`{"type":"codex","access_token":"changed","disabled":false,"proxy_url":"http://external.example:8080","priority":7}`)
	h.entries["a"] = h.entries["a"]
	h.mu.Unlock()
	applyBody, _ := json.Marshal(proxyApplyRequest{PlanID: prepared.PlanID})
	applied, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/apply", Body: applyBody})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Items []domainResult `json:"items"`
	}
	if err := json.Unmarshal(applied.Body, &result); err != nil || len(result.Items) != 1 {
		t.Fatalf("apply=%s err=%v", applied.Body, err)
	}
	if result.Items[0].OK || result.Items[0].ErrorCode != "stale_preview" {
		t.Fatalf("result=%#v", result.Items[0])
	}
	if len(h.saves) != 0 {
		t.Fatalf("stale preview saved %d times", len(h.saves))
	}
}

func TestStaticResourceContainsNoDynamicCredentialData(t *testing.T) {
	svc := New(config.Config{}, nil, nil, nil)
	registered, err := svc.RegisterManagement(context.Background(), pluginapi.ManagementRegistrationRequest{})
	if err != nil || len(registered.Resources) != 1 {
		t.Fatalf("registered=%#v err=%v", registered, err)
	}
	resp, err := registered.Resources[0].Handler.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	body := string(resp.Body)
	for _, secret := range []string{"access_token", "proxy-password", "Bearer test-management-key", "management-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("resource leaked %q", secret)
		}
	}
}
func TestProxyPreviewRequiresRuntimeRevision(t *testing.T) {
	h := newManagementHost()
	entry := h.entries["a"]
	entry.Size = 0
	entry.ModTime = time.Time{}
	entry.UpdatedAt = time.Time{}
	h.entries["a"] = entry
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	proxyURL := "http://new.example:8080"
	body, _ := json.Marshal(ProxyPreviewRequest{Changes: []ProxyChange{{AuthIndex: "a", ProxyURL: &proxyURL}}})
	resp, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnprocessableEntity || strings.Contains(string(resp.Body), `"plan_id":"plan-`) {
		t.Fatalf("status=%d body=%s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(string(resp.Body), `"error_code":"revision_unavailable"`) {
		t.Fatalf("missing revision error: %s", resp.Body)
	}
}
