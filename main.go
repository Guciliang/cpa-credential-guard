package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct { void* ptr; size_t len; } cliproxy_buffer;
typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);
typedef struct { uint32_t abi_version; void* host_ctx; cliproxy_host_call_fn call; cliproxy_host_free_fn free_buffer; } cliproxy_host_api;
typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);
typedef struct { uint32_t abi_version; cliproxy_plugin_call_fn call; cliproxy_plugin_free_fn free_buffer; cliproxy_plugin_shutdown_fn shutdown; } cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);
static const cliproxy_host_api* stored_host;
static void store_host_api(const cliproxy_host_api* host) { stored_host = host; }
static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) return 1;
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}
static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) stored_host->free_buffer(ptr, len);
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"unsafe"

	"cpa-credential-guard/internal/app"
	"cpa-credential-guard/internal/config"
	"cpa-credential-guard/internal/host"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const pluginID = "cpa-credential-guard"

var (
	controllerMu sync.RWMutex
	controller   *app.Controller
	lifecycleMu  sync.Mutex
)

type envelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *envelopeError  `json:"error,omitempty"`
}
type envelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type lifecycleRequest struct {
	ConfigYAML []byte `json:"config_yaml"`
}
type registration struct {
	SchemaVersion uint32                   `json:"schema_version"`
	Metadata      pluginapi.Metadata       `json:"metadata"`
	Capabilities  registrationCapabilities `json:"capabilities"`
}
type registrationCapabilities struct {
	UsagePlugin   bool `json:"usage_plugin"`
	ManagementAPI bool `json:"management_api"`
}

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(rawHost *C.cliproxy_host_api, plugin *C.cliproxy_plugin_api) C.int {
	if plugin == nil {
		return 1
	}
	C.store_host_api(rawHost)
	plugin.abi_version = C.uint32_t(pluginabi.ABIVersion)
	plugin.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	plugin.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	plugin.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponse(response, errorEnvelope("invalid_method", "method is required"))
		return 1
	}
	var raw []byte
	if request != nil && requestLen > 0 {
		raw = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}
	result, err := handleMethod(C.GoString(method), raw)
	if err != nil {
		writeResponse(response, errorEnvelope("plugin_error", safeError(err)))
		return 1
	}
	writeResponse(response, result)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, _ C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()
	shutdownController()
}

func handleMethod(method string, raw []byte) ([]byte, error) {
	switch method {
	case pluginabi.MethodPluginRegister, pluginabi.MethodPluginReconfigure:
		var req lifecycleRequest
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &req); err != nil {
				return nil, errors.New("invalid lifecycle request")
			}
		}
		if err := configure(req.ConfigYAML); err != nil {
			return nil, err
		}
		return okEnvelope(pluginRegistration())
	case pluginabi.MethodPluginShutdown:
		cliproxyPluginShutdown()
		return okEnvelope(map[string]any{})
	case pluginabi.MethodPluginQuiesce:
		lifecycleMu.Lock()
		shutdownController()
		lifecycleMu.Unlock()
		return okEnvelope(map[string]any{})
	case pluginabi.MethodUsageHandle:
		var record pluginapi.UsageRecord
		if err := json.Unmarshal(raw, &record); err != nil {
			return nil, errors.New("invalid usage record")
		}
		controllerMu.RLock()
		current := controller
		controllerMu.RUnlock()
		if current != nil {
			current.HandleUsage(context.Background(), record)
		}
		return okEnvelope(map[string]any{})
	case pluginabi.MethodManagementRegister:
		controllerMu.RLock()
		current := controller
		controllerMu.RUnlock()
		if current == nil {
			return okEnvelope(pluginapi.ManagementRegistrationResponse{})
		}
		var req pluginapi.ManagementRegistrationRequest
		_ = json.Unmarshal(raw, &req)
		response, err := current.Management().RegisterManagement(context.Background(), req)
		if err != nil {
			return nil, err
		}
		return okEnvelope(dynamicManagementRegistration(response))
	case pluginabi.MethodManagementHandle:
		var req pluginapi.ManagementRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, errors.New("invalid management request")
		}
		controllerMu.RLock()
		current := controller
		controllerMu.RUnlock()
		if current == nil {
			return okEnvelope(pluginapi.ManagementResponse{StatusCode: http.StatusServiceUnavailable, Headers: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"error":"plugin_not_configured"}`)})
		}
		response, err := current.HandleManagement(context.Background(), req)
		if err != nil {
			return nil, err
		}
		return okEnvelope(response)
	default:
		return errorEnvelope("unknown_method", "unknown plugin method"), nil
	}
}

func dynamicManagementRegistration(response pluginapi.ManagementRegistrationResponse) pluginapi.ManagementRegistrationResponse {
	// ManagementHandler values are in-process interfaces. The CPA dynamic-library
	// adapter reconstructs them after decoding the route table and dispatches
	// requests through MethodManagementHandle, so serializing a concrete handler
	// here would produce an object that the host cannot decode as an interface.
	for i := range response.Routes {
		response.Routes[i].Handler = nil
	}
	for i := range response.Resources {
		response.Resources[i].Handler = nil
	}
	return response
}

func configure(raw []byte) error {
	lifecycleMu.Lock()
	defer lifecycleMu.Unlock()

	cfg, err := config.Parse(raw)
	if err != nil {
		// Keep the currently running controller alive when the replacement
		// configuration is invalid. A failed reconfigure must not turn a
		// recoverable configuration typo into an outage.
		return err
	}

	// Construct and validate the replacement before touching the current
	// controller. The replacement is stopped until it is published, so a
	// successful reconfigure cannot run two recovery workers at once.
	next, err := app.NewStopped(context.Background(), cfg, host.New(hostCallback))
	if err != nil {
		return err
	}
	controllerMu.Lock()
	previous := controller
	if previous != nil {
		// Keep the lifecycle lock while quiescing the old instance. Calls that
		// already acquired its pointer are tracked by Controller.Shutdown;
		// new calls wait until the replacement is published.
		previous.Shutdown()
	}
	controller = next
	controllerMu.Unlock()
	next.Start()
	return nil
}

func shutdownController() {
	controllerMu.Lock()
	current := controller
	controller = nil
	controllerMu.Unlock()
	if current != nil {
		current.Shutdown()
	}
}

var (
	pluginVersion    = "0.1.7"
	pluginRepository = "https://github.com/Guciliang/cpa-credential-guard"
)

func pluginRegistration() registration {
	return registration{SchemaVersion: pluginabi.SchemaVersion, Metadata: pluginapi.Metadata{Name: "CPA 凭证守护", Version: pluginVersion, Author: "CPA 凭证守护贡献者", GitHubRepository: pluginRepository, ConfigFields: configFields()}, Capabilities: registrationCapabilities{UsagePlugin: true, ManagementAPI: true}}
}
func configFields() []pluginapi.ConfigField {
	return []pluginapi.ConfigField{
		{Name: "enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "启用 Codex 额度观察和受保护的恢复。"},
		{Name: "state_dir", Type: pluginapi.ConfigFieldTypeString, Description: "持久化插件状态目录；不能为空。"},
		{Name: "recovery_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "启用周期性恢复扫描。"},
		{Name: "scan_interval", Type: pluginapi.ConfigFieldTypeString, Description: "恢复扫描间隔；最短为十分钟。"},
		{Name: "initial_backoff", Type: pluginapi.ConfigFieldTypeString, Description: "有上限的初始恢复退避时间。"},
		{Name: "max_backoff", Type: pluginapi.ConfigFieldTypeString, Description: "有上限的最大恢复退避时间。"},
		{Name: "probe_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "启用精确凭证的 Codex 额度清单探测。"},
		{Name: "probe_provider", Type: pluginapi.ConfigFieldTypeEnum, EnumValues: []string{"codex"}, Description: "MVP 恢复提供方。"},
		{Name: "probe_model", Type: pluginapi.ConfigFieldTypeString, Description: "用于未来兼容的提示模型；MVP 探测不会发送该字段。"},
		{Name: "probe_timeout", Type: pluginapi.ConfigFieldTypeString, Description: "有上限的健康探测超时时间。"},
		{Name: "quota_detection_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "启用保守的已完成请求额度分类。"},
		{Name: "detect_http_429", Type: pluginapi.ConfigFieldTypeBoolean, Description: "默认仅在存在明确额度证据时识别 HTTP 429。"},
		{Name: "classify_generic_rate_limit", Type: pluginapi.ConfigFieldTypeBoolean, Description: "选择启用通用限流分类，但误判风险更高。"},
		{Name: "proxy_management_enabled", Type: pluginapi.ConfigFieldTypeBoolean, Description: "启用代理预览、修改和无令牌测试。"},
	}
}

func hostCallback(ctx context.Context, method string, payload []byte) (json.RawMessage, error) {
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))
	var requestPtr *C.uint8_t
	if len(payload) > 0 {
		ptr := C.CBytes(payload)
		if ptr == nil {
			return nil, errors.New("host callback allocation failed")
		}
		defer C.free(ptr)
		requestPtr = (*C.uint8_t)(ptr)
	}
	var response C.cliproxy_buffer
	callCode := C.call_host_api(cMethod, requestPtr, C.size_t(len(payload)), &response)
	var raw []byte
	if response.ptr != nil && response.len > 0 {
		raw = C.GoBytes(response.ptr, C.int(response.len))
	}
	if response.ptr != nil {
		C.free_host_buffer(response.ptr, response.len)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("host callback returned no response (code=%d)", int(callCode))
	}
	var env pluginabi.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, errors.New("invalid host callback envelope")
	}
	if !env.OK {
		if env.Error != nil {
			return nil, errors.New(env.Error.Code)
		}
		return nil, errors.New("host callback failed")
	}
	if callCode != 0 {
		return nil, fmt.Errorf("host callback returned code %d", int(callCode))
	}
	return append(json.RawMessage(nil), env.Result...), nil
}

func okEnvelope(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{OK: true, Result: raw})
}
func errorEnvelope(code, message string) []byte {
	raw, _ := json.Marshal(envelope{OK: false, Error: &envelopeError{Code: code, Message: message}})
	return raw
}
func writeResponse(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}
func safeError(err error) string {
	if err == nil {
		return "plugin_error"
	}
	// Lifecycle errors are returned to CPA diagnostics, but host/network
	// messages may contain paths or response fragments. Keep this boundary
	// stable and secret-free.
	return "plugin_error"
}
