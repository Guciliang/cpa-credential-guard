// Package codexhealth implements the exact-credential Codex wham/usage
// recovery probe. Access tokens are accepted only for one in-memory request and
// are never returned by this package.
package codexhealth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/proxy"
	"cpa-credential-guard/internal/quota"
)

const UsageURL = "https://chatgpt.com/backend-api/wham/usage"
const WakeURL = "https://chatgpt.com/backend-api/codex/responses"
const WakeModel = "gpt-5.6-luna"
const WakePrompt = "Hello"
const MaxResponseBody = 256 << 10
const MaxWakeResponseBody = 512 << 10

const maxCredentialHeaderValue = 8 << 10

var errInvalidProxy = errors.New("proxy URL is malformed")

type Result struct{ Summary domain.ProbeSummary }

type WakeResult struct {
	StatusCode int
	ErrorCode  string
	Completed  bool
}

type Client struct {
	Timeout      time.Duration
	RoundTripper http.RoundTripper
	Now          func() time.Time
}

func NewClient() *Client { return &Client{Timeout: 10 * time.Second, Now: time.Now} }

// Probe accepts complete credential JSON only at the boundary. It extracts
// known Codex fields transiently, sends one GET, and returns safe metadata.
func (c *Client) Probe(ctx context.Context, raw []byte) (domain.ProbeSummary, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	if c != nil && c.Now != nil {
		now = c.Now()
	}
	start := time.Now()
	accessToken, accountID, proxyURL, err := extract(raw)
	if err != nil {
		if errors.Is(err, errInvalidProxy) {
			return domain.ProbeSummary{At: now.UTC(), Status: domain.ProbeError, SafeError: "proxy_setup_failed"}, nil
		}
		return domain.ProbeSummary{At: now.UTC(), Status: domain.ProbeAmbiguous, SafeError: "missing_access_token"}, nil
	}
	// Keep credential material scoped to this function. It is used only while
	// constructing the one request below and is never placed in a result, log,
	// or persistent record.
	defer func() { accessToken = ""; accountID = ""; proxyURL = "" }()
	if c == nil {
		return domain.ProbeSummary{At: now.UTC(), Status: domain.ProbeAmbiguous, SafeError: "health_client_unavailable"}, nil
	}
	timeout := c.Timeout
	if timeout <= 0 || timeout > 2*time.Minute {
		timeout = 10 * time.Second
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var transport http.RoundTripper = c.RoundTripper
	if transport == nil {
		transport, err = buildTransport(proxyURL, timeout)
		if err != nil {
			return domain.ProbeSummary{At: now.UTC(), Status: domain.ProbeError, SafeError: "proxy_setup_failed"}, nil
		}
	}
	req, err := http.NewRequestWithContext(probeCtx, http.MethodGet, UsageURL, nil)
	if err != nil {
		return domain.ProbeSummary{At: now.UTC(), Status: domain.ProbeError, SafeError: "request_failed"}, nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if accountID != "" {
		req.Header.Set("ChatGPT-Account-ID", accountID)
	}
	resp, err := transport.RoundTrip(req)
	at := now.UTC()
	summary := domain.ProbeSummary{At: at, LatencyMS: time.Since(start).Milliseconds()}
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		summary.Status = domain.ProbeError
		summary.SafeError = safeError(err)
		return summary, nil
	}
	if resp == nil {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "empty_response"
		return summary, nil
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBody+1))
	defer wipeBytes(body)
	if readErr != nil {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "response_read_failed"
		return summary, nil
	}
	if len(body) > MaxResponseBody {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "response_too_large"
		return summary, nil
	}
	summary.HTTPStatus = resp.StatusCode
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		summary.Status = domain.ProbeError
		summary.SafeError = "auth_failed"
		return summary, nil
	}
	envelopeStatus, windows, recognized := quota.ParseInventoryResponse(body, resp.Header, now)
	summary.Windows = windows
	if envelopeStatus != 0 {
		if envelopeStatus < 200 || envelopeStatus >= 300 {
			summary.HTTPStatus = envelopeStatus
			if envelopeStatus == http.StatusUnauthorized || envelopeStatus == http.StatusForbidden {
				summary.Status = domain.ProbeError
				summary.SafeError = "auth_failed"
			} else {
				summary.Status = domain.ProbeAmbiguous
				summary.SafeError = "unexpected_status"
			}
			return summary, nil
		}
		if resp.StatusCode == 0 {
			resp.StatusCode = envelopeStatus
			summary.HTTPStatus = envelopeStatus
		}
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		summary.Status = domain.ProbeError
		summary.SafeError = "auth_failed"
		return summary, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "unexpected_status"
		return summary, nil
	}
	if !recognized || len(windows) == 0 {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "invalid_inventory"
		return summary, nil
	}
	for _, window := range windows {
		if window.IsExhausted() {
			summary.Status = domain.ProbeExhausted
			summary.SafeError = "quota_exhausted"
			return summary, nil
		}
	}
	summary.Status = domain.ProbeSuccess
	return summary, nil
}

func extract(raw []byte) (accessToken, accountID, proxyURL string, err error) {
	if len(raw) == 0 || len(raw) > 512<<10 {
		return "", "", "", errors.New("credential too large")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return "", "", "", errors.New("credential is not an object")
	}
	for _, key := range []string{"access_token", "accessToken"} {
		if value, ok := fields[key]; ok {
			_ = json.Unmarshal(value, &accessToken)
			accessToken = strings.TrimSpace(accessToken)
			if validHeaderValue(accessToken) {
				break
			}
			accessToken = ""
		}
	}
	// A few CPA-compatible Codex fixtures wrap OAuth values under an explicit
	// oauth/tokens object. Do not recursively search arbitrary fields: that
	// could mistake a refresh token, cookie, or unrelated secret for an access
	// token.
	if accessToken == "" {
		for _, container := range []string{"oauth", "tokens"} {
			var nested map[string]json.RawMessage
			if value, ok := fields[container]; ok && json.Unmarshal(value, &nested) == nil {
				for _, key := range []string{"access_token", "accessToken"} {
					if value, ok := nested[key]; ok {
						_ = json.Unmarshal(value, &accessToken)
						accessToken = strings.TrimSpace(accessToken)
						if validHeaderValue(accessToken) {
							break
						}
						accessToken = ""
					}
				}
			}
			if accessToken != "" {
				break
			}
		}
	}
	for _, key := range []string{"account_id", "accountId", "chatgpt_account_id"} {
		if value, ok := fields[key]; ok {
			_ = json.Unmarshal(value, &accountID)
			accountID = strings.TrimSpace(accountID)
			if validHeaderValue(accountID) {
				break
			}
			accountID = ""
		}
	}
	if value, ok := fields["proxy_url"]; ok {
		if err := json.Unmarshal(value, &proxyURL); err != nil {
			return "", "", "", errInvalidProxy
		}
	}
	if accessToken == "" {
		return "", "", "", errors.New("access token is absent")
	}
	return accessToken, accountID, proxyURL, nil
}

func validHeaderValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxCredentialHeaderValue {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return false
		}
	}
	return true
}

func buildTransport(rawProxy string, timeout time.Duration) (http.RoundTripper, error) {
	if strings.TrimSpace(rawProxy) == "" {
		dialer := &net.Dialer{Timeout: timeout}
		return &http.Transport{DialContext: dialer.DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, DisableCompression: true}, nil
	}
	validated, err := proxy.Validate(rawProxy)
	if err != nil {
		return nil, err
	}
	return proxy.BuildTransport(validated.URL, timeout)
}

func safeError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "connection_failed"
}

// Wake performs one fixed, real Codex request. It accepts credential JSON only
// for this in-memory operation and returns only an allow-listed outcome.
func (c *Client) Wake(ctx context.Context, raw []byte, model, effort string) (WakeResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if model != WakeModel || effort != "low" && effort != "medium" && effort != "high" {
		return WakeResult{ErrorCode: "wake_protocol_failed"}, nil
	}
	accessToken, accountID, proxyURL, err := extract(raw)
	if err != nil {
		if errors.Is(err, errInvalidProxy) {
			return WakeResult{ErrorCode: "proxy_setup_failed"}, nil
		}
		return WakeResult{ErrorCode: "missing_access_token"}, nil
	}
	defer func() { accessToken = ""; accountID = ""; proxyURL = "" }()
	if c == nil {
		return WakeResult{ErrorCode: "health_client_unavailable"}, nil
	}
	timeout := c.Timeout
	if timeout <= 0 || timeout > 2*time.Minute {
		timeout = 10 * time.Second
	}
	wakeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var transport http.RoundTripper = c.RoundTripper
	if transport == nil {
		transport, err = buildTransport(proxyURL, timeout)
		if err != nil {
			return WakeResult{ErrorCode: "proxy_setup_failed"}, nil
		}
	}
	payload := map[string]any{
		"model":     model,
		"stream":    true,
		"store":     false,
		"reasoning": map[string]string{"effort": effort},
		"input":     []any{map[string]any{"type": "message", "role": "user", "content": []any{map[string]string{"type": "input_text", "text": WakePrompt}}}},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return WakeResult{ErrorCode: "wake_protocol_failed"}, nil
	}
	defer wipeBytes(body)
	req, err := http.NewRequestWithContext(wakeCtx, http.MethodPost, WakeURL, bytes.NewReader(body))
	if err != nil {
		return WakeResult{ErrorCode: "wake_request_failed"}, nil
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	if accountID != "" {
		req.Header.Set("ChatGPT-Account-ID", accountID)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "text/event-stream")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		return WakeResult{ErrorCode: safeWakeError(err)}, nil
	}
	if resp == nil {
		return WakeResult{ErrorCode: "wake_protocol_failed"}, nil
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return WakeResult{StatusCode: resp.StatusCode, ErrorCode: "wake_auth_failed"}, nil
	}
	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusPaymentRequired {
		return WakeResult{StatusCode: resp.StatusCode, ErrorCode: "wake_quota_exhausted"}, nil
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(resp.Body, MaxWakeResponseBody+1))
	defer wipeBytes(responseBody)
	if readErr != nil {
		return WakeResult{StatusCode: resp.StatusCode, ErrorCode: "wake_protocol_failed"}, nil
	}
	if len(responseBody) > MaxWakeResponseBody {
		return WakeResult{StatusCode: resp.StatusCode, ErrorCode: "wake_protocol_failed"}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// The response was received, but an unexpected HTTP status is a
		// protocol/remote-contract failure rather than a transport failure;
		// do not spend the bounded retry budget on an invalid request contract.
		return WakeResult{StatusCode: resp.StatusCode, ErrorCode: "wake_protocol_failed"}, nil
	}
	if !validWakeResponse(responseBody, resp.Header.Get("Content-Type")) {
		return WakeResult{StatusCode: resp.StatusCode, ErrorCode: "wake_protocol_failed"}, nil
	}
	return WakeResult{StatusCode: resp.StatusCode, ErrorCode: "wake_success", Completed: true}, nil
}

// QuotaObservationFromProbe converts a safe health-check result into the
// shared persistence projection. It deliberately preserves no response body
// or credential-bound material.
func QuotaObservationFromProbe(authIndex, identityHash string, summary domain.ProbeSummary) domain.QuotaObservation {
	status := domain.QuotaUnknown
	safeError := domain.SafeCode(summary.SafeError)
	if safeError == "unknown" {
		safeError = "quota_unknown"
	}
	switch summary.Status {
	case domain.ProbeSuccess:
		status = domain.QuotaAvailable
	case domain.ProbeExhausted:
		status = domain.QuotaExhausted
	case domain.ProbeError, domain.ProbeAmbiguous:
		if safeError == "" {
			safeError = "quota_unknown"
		}
	}
	checkedAt := summary.At
	if checkedAt.IsZero() {
		checkedAt = time.Now().UTC()
	}
	resetAt := quota.LatestFutureReset(summary.Windows, checkedAt)
	return domain.QuotaObservation{AuthIndex: authIndex, IdentityHash: identityHash, Status: status, ResetAt: resetAt, CheckedAt: checkedAt.UTC(), SafeError: safeError, Windows: domain.SafeQuotaWindows(summary.Windows)}
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func safeWakeError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	return "wake_request_failed"
}

func validWakeResponse(body []byte, contentType string) bool {
	if len(body) == 0 {
		return false
	}
	if strings.Contains(strings.ToLower(contentType), "text/event-stream") || bytes.Contains(body, []byte("data:")) {
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "data:") {
				continue
			}
			data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			var event map[string]any
			if json.Unmarshal([]byte(data), &event) != nil {
				continue
			}
			if event["type"] == "response.completed" {
				return true
			}
			if response, ok := event["response"].(map[string]any); ok && response["status"] == "completed" {
				return true
			}
		}
		return false
	}
	var response map[string]any
	if json.Unmarshal(body, &response) != nil {
		return false
	}
	if validCompletedResponse(response) {
		return true
	}
	if nested, ok := response["response"].(map[string]any); ok && validCompletedResponse(nested) {
		return true
	}
	return false
}

func validCompletedResponse(response map[string]any) bool {
	if response == nil || response["status"] != "completed" {
		return false
	}
	// A Responses success is not established by the status field (or an id)
	// alone. Require a non-empty output structure so an error envelope or a
	// truncated `{status: completed}` response cannot consume a wake window.
	if output, ok := response["output"].([]any); ok {
		if len(output) == 0 {
			return false
		}
		for _, rawItem := range output {
			item, ok := rawItem.(map[string]any)
			if !ok || strings.TrimSpace(stringValue(item["type"])) == "" || !validOutputItem(item) {
				return false
			}
		}
		return true
	}
	if outputText, ok := response["output_text"].(string); ok && strings.TrimSpace(outputText) != "" {
		return true
	}
	return false
}

func validOutputItem(item map[string]any) bool {
	if content, ok := item["content"].([]any); ok {
		if len(content) == 0 {
			return false
		}
		for _, rawPart := range content {
			part, ok := rawPart.(map[string]any)
			if !ok || strings.TrimSpace(stringValue(part["type"])) == "" {
				return false
			}
			if strings.TrimSpace(stringValue(part["text"])) == "" && strings.TrimSpace(stringValue(part["refusal"])) == "" && strings.TrimSpace(stringValue(part["arguments"])) == "" {
				return false
			}
		}
		return true
	}
	if summary, ok := item["summary"].([]any); ok {
		return len(summary) > 0
	}
	return strings.TrimSpace(stringValue(item["arguments"])) != ""
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

// ParseResponse is exported for deterministic tests and adapters that already
// performed the bounded HTTP request. It accepts no credential material.
func ParseResponse(status int, headers http.Header, body []byte, now time.Time) domain.ProbeSummary {
	if now.IsZero() {
		now = time.Now()
	}
	summary := domain.ProbeSummary{At: now.UTC(), HTTPStatus: status}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		summary.Status = domain.ProbeError
		summary.SafeError = "auth_failed"
		return summary
	}
	if len(body) > MaxResponseBody {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "response_too_large"
		return summary
	}
	windows, recognized := quota.ParseInventory(string(body), headers, now)
	summary.Windows = windows
	if envelopeStatus := quota.ResponseStatus(body); envelopeStatus != 0 {
		if status == 0 {
			status = envelopeStatus
			summary.HTTPStatus = envelopeStatus
		}
		if envelopeStatus < 200 || envelopeStatus >= 300 {
			summary.HTTPStatus = envelopeStatus
			if envelopeStatus == http.StatusUnauthorized || envelopeStatus == http.StatusForbidden {
				summary.Status = domain.ProbeError
				summary.SafeError = "auth_failed"
			} else {
				summary.Status = domain.ProbeAmbiguous
				summary.SafeError = "unexpected_status"
			}
			return summary
		}
	}
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		summary.Status = domain.ProbeError
		summary.SafeError = "auth_failed"
		return summary
	}
	if status < 200 || status >= 300 {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "unexpected_status"
		return summary
	}
	if !recognized || len(windows) == 0 {
		summary.Status = domain.ProbeAmbiguous
		summary.SafeError = "invalid_inventory"
		return summary
	}
	for _, window := range windows {
		if window.IsExhausted() {
			summary.Status = domain.ProbeExhausted
			summary.SafeError = "quota_exhausted"
			return summary
		}
	}
	summary.Status = domain.ProbeSuccess
	return summary
}
