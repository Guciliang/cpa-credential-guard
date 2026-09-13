package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestRegistrationDeclaresOnlyObservationAndManagement(t *testing.T) {
	registration := pluginRegistration()
	if registration.SchemaVersion != pluginabi.SchemaVersion {
		t.Fatalf("schema=%d", registration.SchemaVersion)
	}
	if !registration.Capabilities.UsagePlugin || !registration.Capabilities.ManagementAPI {
		t.Fatalf("capabilities=%#v", registration.Capabilities)
	}
	encoded, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, forbidden := range []string{"scheduler", "router", "executor", "interceptor", "retry"} {
		if containsCapability(body, forbidden) {
			t.Fatalf("registration contains forbidden capability %q: %s", forbidden, body)
		}
	}
}
func TestRegistrationPublishesOwnRepositoryMetadata(t *testing.T) {
	metadata := pluginRegistration().Metadata
	if metadata.GitHubRepository != "https://github.com/Guciliang/cpa-credential-guard" {
		t.Fatalf("repository=%q", metadata.GitHubRepository)
	}
	if metadata.Version == "" || strings.HasPrefix(metadata.Version, "v") {
		t.Fatalf("version=%q must be a release version without the v prefix", metadata.Version)
	}
}

func containsCapability(body, key string) bool {
	var value map[string]any
	_ = json.Unmarshal([]byte(body), &value)
	caps, _ := value["capabilities"].(map[string]any)
	_, ok := caps[key]
	return ok
}
func TestDynamicManagementRegistrationOmitsInProcessHandlers(t *testing.T) {
	response := dynamicManagementRegistration(pluginapi.ManagementRegistrationResponse{
		Routes:    []pluginapi.ManagementRoute{{Method: http.MethodGet, Path: "/status", Handler: testManagementHandler{}}},
		Resources: []pluginapi.ResourceRoute{{Path: "/index.html", Handler: testManagementHandler{}}},
	})
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if strings.Contains(body, `"Handler":{`) {
		t.Fatalf("dynamic registration serialized an in-process handler: %s", body)
	}
	if !strings.Contains(body, `"Handler":null`) {
		t.Fatalf("dynamic registration did not preserve nil handler fields: %s", body)
	}
}

type testManagementHandler struct{}

func (testManagementHandler) HandleManagement(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	return pluginapi.ManagementResponse{}, nil
}
