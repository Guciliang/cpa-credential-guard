package management

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"cpa-credential-guard/internal/config"
	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/profiles"
	"cpa-credential-guard/internal/proxy"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type managementRoundTripper func(*http.Request) (*http.Response, error)

func (f managementRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestProfileEditRetainsOrReplacesURLWithoutRedactionLeak(t *testing.T) {
	profileStore, _, err := profiles.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profileStore.Close()
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, nil, nil, nil)
	svc.SetProfileStore(profileStore)
	create := func(body string) (pluginapi.ManagementResponse, error) {
		return svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/profiles", Headers: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(body)})
	}
	created, err := create(`{"remark":"线路一","proxy_url":"http://user:secret@proxy.example:8080"}`)
	if err != nil || created.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d body=%s err=%v", created.StatusCode, created.Body, err)
	}
	var createdPayload struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(created.Body, &createdPayload); err != nil || createdPayload.Profile.ID == "" {
		t.Fatalf("created=%s err=%v", created.Body, err)
	}
	id := createdPayload.Profile.ID
	duplicate, err := create(`{"remark":"线路一","proxy_url":"http://other.example:8080"}`)
	if err != nil || duplicate.StatusCode != http.StatusUnprocessableEntity || strings.Contains(string(duplicate.Body), "secret") {
		t.Fatalf("duplicate status=%d body=%s err=%v", duplicate.StatusCode, duplicate.Body, err)
	}
	retained, err := create(`{"id":"` + id + `","remark":"线路一改名"}`)
	if err != nil || retained.StatusCode != http.StatusOK || strings.Contains(string(retained.Body), "secret") || strings.Contains(string(retained.Body), "fallback_auth_indexes") {
		t.Fatalf("retained status=%d body=%s err=%v", retained.StatusCode, retained.Body, err)
	}
	profile, ok := profileStore.Get(id)
	if !ok || profile.ProxyURL != "http://user:secret@proxy.example:8080" || profile.Remark != "线路一改名" {
		t.Fatalf("retained profile=%#v ok=%v", profile, ok)
	}
	replacement := `socks5://next:private@other.example:1080`
	replaced, err := create(`{"id":"` + id + `","remark":"线路二","proxy_url":"` + replacement + `"}`)
	if err != nil || replaced.StatusCode != http.StatusOK || strings.Contains(string(replaced.Body), "private") {
		t.Fatalf("replaced status=%d body=%s err=%v", replaced.StatusCode, replaced.Body, err)
	}
	profile, ok = profileStore.Get(id)
	if !ok || profile.ProxyURL != "socks5h://next:private@other.example:1080" {
		t.Fatalf("replacement profile=%#v ok=%v", profile, ok)
	}
	for _, body := range []string{`{"id":"` + id + `","remark":"线路三","proxy_url":"not-a-url"}`, `{"id":"missing","remark":"未知"}`} {
		response, err := create(body)
		if err != nil || (response.StatusCode != http.StatusUnprocessableEntity && response.StatusCode != http.StatusNotFound) || strings.Contains(string(response.Body), "private") || strings.Contains(string(response.Body), "secret") {
			t.Fatalf("invalid edit status=%d body=%s err=%v", response.StatusCode, response.Body, err)
		}
	}
}

func TestExplicitFallbackPreviewApplyAndRestoreUsesSafeProjection(t *testing.T) {
	h := newManagementHost()
	profileStore, _, err := profiles.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profileStore.Close()
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	svc.SetProfileStore(profileStore)
	original, err := profileStore.Upsert("original", "主线路", "http://original.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	mode := "direct"
	if _, err := profileStore.SaveWithFallback(original.ID, original.Remark, nil, &mode, nil); err != nil {
		t.Fatal(err)
	}
	h.raw["a"] = json.RawMessage(`{"type":"codex","access_token":"secret-a","disabled":false,"proxy_url":"http://original.example:8080","priority":7}`)
	forgedFallback := &proxyFallbackRequest{Action: "activate", ProfileID: original.ID, AuthIndexes: []string{"b"}}
	forgedBody, _ := json.Marshal(ProxyPreviewRequest{Changes: []ProxyChange{{AuthIndex: "b", Clear: true}}, Fallback: forgedFallback})
	forged, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: forgedBody})
	if err != nil || forged.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("forged fallback status=%d body=%s err=%v", forged.StatusCode, forged.Body, err)
	}
	fallback := &proxyFallbackRequest{Action: "activate", ProfileID: original.ID, AuthIndexes: []string{"a"}}
	previewBody, _ := json.Marshal(ProxyPreviewRequest{Changes: []ProxyChange{{AuthIndex: "a", Clear: true}}, Fallback: fallback})
	preview, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: previewBody})
	if err != nil || preview.StatusCode != http.StatusOK {
		t.Fatalf("fallback preview status=%d body=%s err=%v", preview.StatusCode, preview.Body, err)
	}
	var planned struct {
		PlanID string `json:"plan_id"`
	}
	if err := json.Unmarshal(preview.Body, &planned); err != nil || planned.PlanID == "" || strings.Contains(string(preview.Body), "fallback_auth_indexes") {
		t.Fatalf("fallback preview=%s err=%v", preview.Body, err)
	}
	applyBody, _ := json.Marshal(proxyApplyRequest{PlanID: planned.PlanID})
	applied, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/apply", Body: applyBody})
	if err != nil || applied.StatusCode != http.StatusOK {
		t.Fatalf("fallback apply status=%d body=%s err=%v", applied.StatusCode, applied.Body, err)
	}
	active, ok := profileStore.Get(original.ID)
	if !ok || active.Projection.FallbackState != "active" || len(active.FallbackAuthIndexes) != 1 {
		t.Fatalf("active fallback=%#v ok=%v", active, ok)
	}
	if strings.Contains(string(applied.Body), "secret") || strings.Contains(string(applied.Body), "user:") {
		t.Fatalf("fallback apply exposed proxy credentials: %s", applied.Body)
	}
	restore := &proxyFallbackRequest{Action: "restore", ProfileID: original.ID}
	restoreBody, _ := json.Marshal(ProxyPreviewRequest{Fallback: restore})
	restorePreview, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: restoreBody})
	if err != nil || restorePreview.StatusCode != http.StatusOK {
		t.Fatalf("restore preview status=%d body=%s err=%v", restorePreview.StatusCode, restorePreview.Body, err)
	}
	if err := json.Unmarshal(restorePreview.Body, &planned); err != nil || planned.PlanID == "" {
		t.Fatalf("restore preview=%s err=%v", restorePreview.Body, err)
	}
	restored, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/apply", Body: func() []byte { body, _ := json.Marshal(proxyApplyRequest{PlanID: planned.PlanID}); return body }()})
	if err != nil || restored.StatusCode != http.StatusOK {
		t.Fatalf("restore apply status=%d body=%s err=%v", restored.StatusCode, restored.Body, err)
	}
	final, _ := profileStore.Get(original.ID)
	if final.Projection.FallbackState != "configured" || len(final.FallbackAuthIndexes) != 0 {
		t.Fatalf("final fallback=%#v", final)
	}
}

func TestProxyRemarksDrivePreviewApplyAndConnectivity(t *testing.T) {
	h := newManagementHost()
	profileStore, _, err := profiles.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer profileStore.Close()
	svc := New(config.Config{Enabled: true, ProxyManagementEnabled: true}, credentials.NewRepository(h), nil, nil)
	svc.SetProfileStore(profileStore)
	svc.SetChecker(&proxy.Checker{Timeout: time.Second, RoundTripper: managementRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header), Request: request}, nil
	})})

	profileBody := []byte(`{"remark":"香港主线路","proxy_url":"http://proxy-user:proxy-secret@PROXY.EXAMPLE:8080"}`)
	created, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/profiles", Body: profileBody})
	if err != nil || created.StatusCode != http.StatusOK {
		t.Fatalf("create status=%d body=%s err=%v", created.StatusCode, created.Body, err)
	}
	if strings.Contains(string(created.Body), "proxy-secret") || strings.Contains(string(created.Body), "proxy-user") {
		t.Fatalf("profile response leaked proxy credentials: %s", created.Body)
	}
	var createdPayload struct {
		Profile struct {
			ID string `json:"id"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(created.Body, &createdPayload); err != nil || createdPayload.Profile.ID == "" {
		t.Fatalf("created=%s err=%v", created.Body, err)
	}

	previewBody, _ := json.Marshal(ProxyPreviewRequest{Changes: []ProxyChange{{AuthIndex: "a", ProfileID: createdPayload.Profile.ID}}})
	preview, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/preview", Body: previewBody})
	if err != nil || preview.StatusCode != http.StatusOK {
		t.Fatalf("preview status=%d body=%s err=%v", preview.StatusCode, preview.Body, err)
	}
	if strings.Contains(string(preview.Body), "proxy-secret") || !strings.Contains(string(preview.Body), "香港主线路") {
		t.Fatalf("preview projection is unsafe or missing remark: %s", preview.Body)
	}
	var prepared struct {
		PlanID string `json:"plan_id"`
	}
	if err := json.Unmarshal(preview.Body, &prepared); err != nil || prepared.PlanID == "" {
		t.Fatalf("preview=%s err=%v", preview.Body, err)
	}

	applyBody, _ := json.Marshal(proxyApplyRequest{PlanID: prepared.PlanID})
	applied, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/apply", Body: applyBody})
	if err != nil || applied.StatusCode != http.StatusOK {
		t.Fatalf("apply status=%d body=%s err=%v", applied.StatusCode, applied.Body, err)
	}
	if !strings.Contains(string(h.raw["a"]), "proxy-secret") {
		t.Fatalf("host save did not preserve the selected profile URL: %s", h.raw["a"])
	}
	if strings.Contains(string(applied.Body), "proxy-secret") {
		t.Fatalf("apply response leaked proxy credentials: %s", applied.Body)
	}
	status, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodGet, Path: "/status"})
	if err != nil || status.StatusCode != http.StatusOK || strings.Contains(string(status.Body), "proxy-secret") || !strings.Contains(string(status.Body), "香港主线路") {
		t.Fatalf("status projection is unsafe or missing profile remark: status=%d body=%s err=%v", status.StatusCode, status.Body, err)
	}

	tested, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/test", Body: []byte(`{"profile_ids":["` + createdPayload.Profile.ID + `"]}`)})
	if err != nil || tested.StatusCode != http.StatusOK || !strings.Contains(string(tested.Body), "香港主线路") || !strings.Contains(string(tested.Body), `"ok":true`) {
		t.Fatalf("test status=%d body=%s err=%v", tested.StatusCode, tested.Body, err)
	}
	if strings.Contains(string(tested.Body), "proxy-secret") {
		t.Fatalf("test response leaked proxy credentials: %s", tested.Body)
	}

	deleted, err := svc.HandleManagement(context.Background(), pluginapi.ManagementRequest{Method: http.MethodPost, Path: "/proxy/profiles/delete", Body: []byte(`{"profile_id":"` + createdPayload.Profile.ID + `"}`)})
	if err != nil || deleted.StatusCode != http.StatusOK {
		t.Fatalf("delete status=%d body=%s err=%v", deleted.StatusCode, deleted.Body, err)
	}
}
