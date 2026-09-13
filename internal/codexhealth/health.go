// Package codexhealth implements the exact-credential Codex wham/usage
// recovery probe. Access tokens are accepted only for one in-memory request and
// are never returned by this package.
package codexhealth

import (
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
const MaxResponseBody = 256 << 10

var errInvalidProxy = errors.New("proxy URL is malformed")

type Result struct{ Summary domain.ProbeSummary }

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
	if !recognized {
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
	if value == "" {
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
	if !recognized {
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
