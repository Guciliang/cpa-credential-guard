package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"cpa-credential-guard/internal/host"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type fakeHost struct {
	mu                                           sync.Mutex
	entries                                      map[string]pluginapi.HostAuthFileEntry
	payloads                                     map[string]json.RawMessage
	saves                                        []pluginapi.HostAuthSaveRequest
	getCount, runtimeCount, listCount, saveCount int
}

func newFakeHost(raw string) *fakeHost {
	return &fakeHost{entries: map[string]pluginapi.HostAuthFileEntry{"a-1": {AuthIndex: "a-1", ID: "id-1", Name: "auth.json", Provider: "codex", Type: "codex", Size: int64(len(raw)), ModTime: time.Unix(100, 0)}}, payloads: map[string]json.RawMessage{"a-1": json.RawMessage(raw)}}
}
func (h *fakeHost) List(context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.listCount++
	out := make([]pluginapi.HostAuthFileEntry, 0, len(h.entries))
	for _, v := range h.entries {
		out = append(out, v)
	}
	return out, nil
}
func (h *fakeHost) Get(_ context.Context, index string) (pluginapi.HostAuthGetResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.getCount++
	e, ok := h.entries[index]
	if !ok {
		return pluginapi.HostAuthGetResponse{}, errors.New("missing")
	}
	return pluginapi.HostAuthGetResponse{AuthIndex: index, Name: e.Name, Path: e.Path, JSON: append([]byte(nil), h.payloads[index]...)}, nil
}
func (h *fakeHost) GetRuntime(_ context.Context, index string) (pluginapi.HostAuthGetRuntimeResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.runtimeCount++
	e, ok := h.entries[index]
	if !ok {
		return pluginapi.HostAuthGetRuntimeResponse{}, errors.New("missing")
	}
	return pluginapi.HostAuthGetRuntimeResponse{Auth: e}, nil
}
func (h *fakeHost) Save(_ context.Context, req pluginapi.HostAuthSaveRequest) (pluginapi.HostAuthSaveResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.saveCount++
	for index, e := range h.entries {
		if e.Name == req.Name {
			h.payloads[index] = append([]byte(nil), req.JSON...)
			e.Size = int64(len(req.JSON))
			e.ModTime = e.ModTime.Add(time.Second)
			e.UpdatedAt = e.ModTime
			h.entries[index] = e
			h.saves = append(h.saves, req)
			return pluginapi.HostAuthSaveResponse{Name: req.Name}, nil
		}
	}
	return pluginapi.HostAuthSaveResponse{}, errors.New("missing")
}

func TestMutateTopLevelOnlyChangesTarget(t *testing.T) {
	raw := []byte(`{"access_token":"secret","disabled":false,"proxy_url":"http://u:p@example.test:8080/path?q=x","nested":{"a":[1,true,null]}}`)
	updated, changed, err := MutateTopLevel(raw, "disabled", json.RawMessage(`true`), false)
	if err != nil || !changed {
		t.Fatalf("mutation changed=%v err=%v", changed, err)
	}
	var before, after map[string]json.RawMessage
	_ = json.Unmarshal(raw, &before)
	_ = json.Unmarshal(updated, &after)
	for key := range before {
		if key == "disabled" {
			continue
		}
		if !jsonSemanticEqual(before[key], after[key]) {
			t.Fatalf("field %s changed", key)
		}
	}
	var disabled bool
	_ = json.Unmarshal(after["disabled"], &disabled)
	if !disabled {
		t.Fatal("disabled not set")
	}
	cleared, changed, err := MutateTopLevel(updated, "proxy_url", nil, true)
	if err != nil || !changed {
		t.Fatalf("clear changed=%v err=%v", changed, err)
	}
	if _, ok := mapValue(cleared, "proxy_url"); ok {
		t.Fatal("proxy_url still present")
	}
}
func mapValue(raw []byte, key string) (json.RawMessage, bool) {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(raw, &m)
	v, ok := m[key]
	return v, ok
}

func TestResolveRejectsAmbiguousAuthIndex(t *testing.T) {
	h := newFakeHost(`{"access_token":"secret","disabled":false}`)
	h.entries["a-2"] = pluginapi.HostAuthFileEntry{AuthIndex: "a-1", ID: "id-2", Name: "other.json", Provider: "codex", Type: "codex"}
	r := NewRepository(h)
	if _, _, err := r.Resolve(context.Background(), "a-1", ""); err == nil {
		t.Fatal("ambiguous auth index resolved")
	}
}

func TestResolveRejectsAmbiguousAuthIDAcrossProviders(t *testing.T) {
	h := newFakeHost(`{"access_token":"secret","disabled":false}`)
	h.entries["other"] = pluginapi.HostAuthFileEntry{AuthIndex: "other", ID: "id-1", Name: "other.json", Provider: "claude", Type: "claude"}
	r := NewRepository(h)
	if _, _, err := r.Resolve(context.Background(), "id-1", ""); err == nil {
		t.Fatal("ambiguous auth id resolved")
	}
}

func TestSetDisabledPreservesFieldsAndFreshGuards(t *testing.T) {
	h := newFakeHost(`{"access_token":"secret","disabled":false,"priority":7,"proxy_url":"http://old.example:8080","nested":{"x":1}}`)
	r := NewRepository(h)
	result, err := r.SetDisabled(context.Background(), "a-1", true, Guard{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed {
		t.Fatal("expected save")
	}
	if h.saveCount != 1 {
		t.Fatalf("save count=%d", h.saveCount)
	}
	var got map[string]any
	_ = json.Unmarshal(h.saves[0].JSON, &got)
	if got["access_token"] != "secret" || got["priority"].(float64) != 7 || got["disabled"] != true {
		t.Fatalf("saved payload=%v", got)
	}
	if h.getCount < 2 || h.runtimeCount < 2 {
		t.Fatalf("fresh/post-save host calls get=%d runtime=%d", h.getCount, h.runtimeCount)
	}
}
func TestHashJSONDistinguishesLargeNumericCredentialFields(t *testing.T) {
	first := HashJSON([]byte(`{"large_id":9007199254740992}`))
	second := HashJSON([]byte(`{"large_id":9007199254740993}`))
	if first == "" || second == "" || first == second {
		t.Fatalf("hashes=%q %q", first, second)
	}
}

func TestHashJSONRejectsTrailingData(t *testing.T) {
	if got := HashJSON([]byte(`{"access_token":"secret"} trailing`)); got != "" {
		t.Fatalf("hash=%q", got)
	}
}

func TestRepositoryGuardRejectsChangedCredential(t *testing.T) {
	h := newFakeHost(`{"access_token":"secret","disabled":false}`)
	r := NewRepository(h)
	snap, err := r.Snapshot(context.Background(), "a-1")
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.payloads["a-1"] = json.RawMessage(`{"access_token":"changed","disabled":false}`)
	h.mu.Unlock()
	_, err = r.SetProxy(context.Background(), "a-1", "http://proxy.example:8080", false, Guard{ContentHashWithoutDisabled: snap.ContentHashWithoutDisabled})
	if !errors.Is(err, ErrRevisionMismatch) {
		t.Fatalf("error=%v", err)
	}
	if h.saveCount != 0 {
		t.Fatal("changed credential was overwritten")
	}
}

func TestCallbackAdapterDecodesHostEnvelope(t *testing.T) {
	calls := 0
	callback := host.CallbackFromJSON(func(_ context.Context, method string, _ []byte) (int, []byte) {
		calls++
		if method != "host.auth.list" {
			t.Fatal(method)
		}
		return 0, []byte(`{"ok":true,"result":{"files":[]}}`)
	})
	client := host.New(callback)
	files, err := client.List(context.Background())
	if err != nil || len(files) != 0 {
		t.Fatalf("files=%v err=%v", files, err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}
