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
