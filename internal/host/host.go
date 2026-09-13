// Package host is the narrow CPA Host callback adapter used by all credential
// mutations. Management API credentials are intentionally absent from it.
package host

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// Callback is the only ABI dependency required by the rest of the plugin. A
// fake callback can be supplied by unit tests without loading a dynamic lib.
type Callback func(context.Context, string, []byte) (json.RawMessage, error)

type API interface {
	List(context.Context) ([]pluginapi.HostAuthFileEntry, error)
	Get(context.Context, string) (pluginapi.HostAuthGetResponse, error)
	GetRuntime(context.Context, string) (pluginapi.HostAuthGetRuntimeResponse, error)
	Save(context.Context, pluginapi.HostAuthSaveRequest) (pluginapi.HostAuthSaveResponse, error)
}

type Client struct{ callback Callback }

func New(callback Callback) *Client { return &Client{callback: callback} }

func (c *Client) call(ctx context.Context, method string, request any, result any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || c.callback == nil {
		return fmt.Errorf("host callback unavailable")
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encode %s request: %w", method, err)
	}
	raw, err := c.callback(ctx, method, payload)
	if err != nil {
		return fmt.Errorf("%s: %w", method, err)
	}
	if len(raw) == 0 {
		return fmt.Errorf("%s returned an empty result", method)
	}
	if err := json.Unmarshal(raw, result); err != nil {
		return fmt.Errorf("decode %s result: %w", method, err)
	}
	return nil
}

func (c *Client) List(ctx context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	var response struct {
		Files []pluginapi.HostAuthFileEntry `json:"files"`
	}
	if err := c.call(ctx, pluginabi.MethodHostAuthList, map[string]any{}, &response); err != nil {
		return nil, err
	}
	return append([]pluginapi.HostAuthFileEntry(nil), response.Files...), nil
}
func (c *Client) Get(ctx context.Context, index string) (pluginapi.HostAuthGetResponse, error) {
	var response pluginapi.HostAuthGetResponse
	if index == "" {
		return response, fmt.Errorf("auth index is required")
	}
	if err := c.call(ctx, pluginabi.MethodHostAuthGet, pluginapi.HostAuthGetRequest{AuthIndex: index}, &response); err != nil {
		return response, err
	}
	if response.AuthIndex == "" {
		response.AuthIndex = index
	}
	return response, nil
}
func (c *Client) GetRuntime(ctx context.Context, index string) (pluginapi.HostAuthGetRuntimeResponse, error) {
	var response pluginapi.HostAuthGetRuntimeResponse
	if index == "" {
		return response, fmt.Errorf("auth index is required")
	}
	if err := c.call(ctx, pluginabi.MethodHostAuthGetRuntime, pluginapi.HostAuthGetRequest{AuthIndex: index}, &response); err != nil {
		return response, err
	}
	return response, nil
}
func (c *Client) Save(ctx context.Context, request pluginapi.HostAuthSaveRequest) (pluginapi.HostAuthSaveResponse, error) {
	var response pluginapi.HostAuthSaveResponse
	if request.Name == "" || len(request.JSON) == 0 {
		return response, fmt.Errorf("host.auth.save requires name and JSON")
	}
	if err := c.call(ctx, pluginabi.MethodHostAuthSave, request, &response); err != nil {
		return response, err
	}
	return response, nil
}

// CallbackFromJSON is useful for tests and embeds the same envelope contract
// as CPA's dynamic ABI callback.
func CallbackFromJSON(fn func(context.Context, string, []byte) (int, []byte)) Callback {
	return func(ctx context.Context, method string, request []byte) (json.RawMessage, error) {
		code, response := fn(ctx, method, request)
		if len(response) == 0 {
			return nil, fmt.Errorf("callback returned no envelope (code=%d)", code)
		}
		var envelope pluginabi.Envelope
		if err := json.Unmarshal(response, &envelope); err != nil {
			return nil, fmt.Errorf("decode callback envelope: %w", err)
		}
		if !envelope.OK {
			if envelope.Error != nil {
				return nil, fmt.Errorf("%s: %s", envelope.Error.Code, envelope.Error.Message)
			}
			return nil, fmt.Errorf("host callback failed")
		}
		if code != 0 {
			return nil, fmt.Errorf("host callback returned code=%d", code)
		}
		return envelope.Result, nil
	}
}
