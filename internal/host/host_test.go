package host

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestClientAuthCallbacksDecodeSDKContracts(t *testing.T) {
	entry := pluginapi.HostAuthFileEntry{AuthIndex: "a-1", ID: "id-1", Name: "auth.json", Provider: "codex", Type: "codex", Size: 42, ModTime: time.Unix(10, 0).UTC()}
	callback := CallbackFromJSON(func(_ context.Context, method string, request []byte) (int, []byte) {
		switch method {
		case pluginabi.MethodHostAuthList:
			return 0, envelopeResult(t, struct {
				Files []pluginapi.HostAuthFileEntry `json:"files"`
			}{Files: []pluginapi.HostAuthFileEntry{entry}})
		case pluginabi.MethodHostAuthGet:
			var req pluginapi.HostAuthGetRequest
			if err := json.Unmarshal(request, &req); err != nil || req.AuthIndex != entry.AuthIndex {
				t.Fatalf("get request=%s err=%v", request, err)
			}
			return 0, envelopeResult(t, pluginapi.HostAuthGetResponse{AuthIndex: entry.AuthIndex, Name: entry.Name, JSON: json.RawMessage(`{"type":"codex","disabled":false}`)})
		case pluginabi.MethodHostAuthGetRuntime:
			return 0, envelopeResult(t, pluginapi.HostAuthGetRuntimeResponse{Auth: entry})
		case pluginabi.MethodHostAuthSave:
			var req pluginapi.HostAuthSaveRequest
			if err := json.Unmarshal(request, &req); err != nil || req.Name != entry.Name || len(req.JSON) == 0 {
				t.Fatalf("save request=%s err=%v", request, err)
			}
			return 0, envelopeResult(t, pluginapi.HostAuthSaveResponse{Name: req.Name, Path: "/auth/" + req.Name})
		default:
			t.Fatalf("unexpected callback method %q", method)
			return 0, nil
		}
	})
	client := New(callback)
	files, err := client.List(context.Background())
	if err != nil || len(files) != 1 || files[0].AuthIndex != entry.AuthIndex {
		t.Fatalf("files=%#v err=%v", files, err)
	}
	got, err := client.Get(context.Background(), entry.AuthIndex)
	if err != nil || got.Name != entry.Name {
		t.Fatalf("get=%#v err=%v", got, err)
	}
	runtime, err := client.GetRuntime(context.Background(), entry.AuthIndex)
	if err != nil || runtime.Auth.ID != entry.ID {
		t.Fatalf("runtime=%#v err=%v", runtime, err)
	}
	saved, err := client.Save(context.Background(), pluginapi.HostAuthSaveRequest{Name: entry.Name, JSON: json.RawMessage(`{"type":"codex","disabled":true}`)})
	if err != nil || saved.Path == "" {
		t.Fatalf("saved=%#v err=%v", saved, err)
	}
}

func TestCallbackAdapterReturnsSafeHostErrors(t *testing.T) {
	client := New(CallbackFromJSON(func(context.Context, string, []byte) (int, []byte) {
		return 0, []byte(`{"ok":false,"error":{"code":"host_unavailable","message":"sensitive path"}}`)
	}))
	if _, err := client.List(context.Background()); err == nil {
		t.Fatal("expected host callback error")
	}
}

func envelopeResult(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	response, err := json.Marshal(pluginabi.Envelope{OK: true, Result: raw})
	if err != nil {
		t.Fatal(err)
	}
	return response
}
