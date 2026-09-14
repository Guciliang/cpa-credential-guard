// Package proxy validates, redacts, and tests proxy endpoints without
// accepting or loading CPA credential data.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	xproxy "golang.org/x/net/proxy"

	"cpa-credential-guard/internal/domain"
)

const (
	MaxResponseBody = 16 << 10
	DefaultTarget   = "https://www.gstatic.com/generate_204"
)

type Validated struct {
	Raw        string
	URL        *url.URL
	Projection domain.ProxyProjection
}

func Validate(raw string) (Validated, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return Validated{}, errors.New("proxy URL is empty")
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return Validated{}, errors.New("proxy URL contains forbidden characters")
	}
	u, err := url.Parse(value)
	if err != nil || u == nil || u.Opaque != "" {
		return Validated{}, errors.New("proxy URL is malformed")
	}
	if strings.ContainsAny(u.Host, "\x00\r\n") || containsControl(u.Path) || containsControl(u.RawPath) || containsControl(u.RawQuery) {
		return Validated{}, errors.New("proxy URL contains forbidden characters")
	}
	scheme := strings.ToLower(u.Scheme)
	hostname := strings.ToLower(u.Hostname())
	if scheme == "socks5" {
		scheme = "socks5h"
	}
	u.Scheme = scheme
	switch scheme {
	case "http", "https", "socks5h":
	default:
		return Validated{}, fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	if u.Hostname() == "" || u.Port() == "" {
		return Validated{}, errors.New("proxy URL must include host and port")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return Validated{}, errors.New("proxy port is invalid")
	}
	canonicalPort := strconv.Itoa(port)
	u.Host = formatHost(hostname, canonicalPort)
	if u.Fragment != "" {
		return Validated{}, errors.New("proxy URL fragments are not allowed")
	}
	if strings.Contains(u.Host, "@") && u.User == nil {
		return Validated{}, errors.New("proxy URL userinfo is malformed")
	}
	if u.User != nil {
		username := u.User.Username()
		password, _ := u.User.Password()
		if strings.TrimSpace(username) == "" || containsControl(username) || containsControl(password) {
			return Validated{}, errors.New("proxy URL userinfo is invalid")
		}
	}
	endpoint := scheme + "://" + formatHost(hostname, canonicalPort)
	return Validated{Raw: value, URL: u, Projection: domain.ProxyProjection{Configured: true, Endpoint: endpoint, Scheme: scheme, Host: hostname, Port: canonicalPort}}, nil
}

func formatHost(hostname, port string) string {
	if strings.Contains(hostname, ":") {
		return "[" + hostname + "]:" + port
	}
	return hostname + ":" + port
}

func containsControl(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x20 || value[index] == 0x7f {
			return true
		}
	}
	return false
}
func Redact(raw string) domain.ProxyProjection {
	validated, err := Validate(raw)
	if err != nil {
		return domain.ProxyProjection{}
	}
	return validated.Projection
}

// Checker owns a separate token-free transport. The target is fixed and cannot
// be supplied by a management request.
type Checker struct {
	Timeout      time.Duration
	RoundTripper http.RoundTripper
}

type Result struct {
	Projection domain.ProxyProjection
	Reachable  bool
	HTTPStatus int
	Latency    time.Duration
	ErrorCode  string
}

func NewChecker() *Checker { return &Checker{Timeout: 10 * time.Second} }

func (c *Checker) Check(ctx context.Context, rawProxy string) Result {
	if ctx == nil {
		ctx = context.Background()
	}
	validated, err := Validate(rawProxy)
	result := Result{}
	if err != nil {
		result.ErrorCode = "invalid_proxy"
		return result
	}
	result.Projection = validated.Projection
	timeout := 10 * time.Second
	if c != nil {
		timeout = c.Timeout
	}
	if timeout <= 0 || timeout > 2*time.Minute {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	var transport http.RoundTripper
	if c != nil && c.RoundTripper != nil {
		transport = c.RoundTripper
	} else {
		transport, err = BuildTransport(validated.URL, timeout)
		if err != nil {
			result.ErrorCode = "proxy_setup_failed"
			return result
		}
	}
	target := DefaultTarget
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		result.ErrorCode = "target_invalid"
		return result
	}
	req.Header.Set("Accept", "*/*")
	resp, err := transport.RoundTrip(req)
	result.Latency = time.Since(start)
	if err != nil {
		result.ErrorCode = safeNetworkError(err)
		return result
	}
	if resp == nil {
		result.ErrorCode = "empty_response"
		return result
	}
	if resp.Body == nil {
		resp.Body = http.NoBody
	}
	defer resp.Body.Close()
	_, readErr := io.CopyN(io.Discard, resp.Body, MaxResponseBody+1)
	if readErr == nil {
		result.HTTPStatus = resp.StatusCode
		result.Reachable = true
		result.ErrorCode = "response_too_large"
		return result
	}
	if readErr != io.EOF {
		result.ErrorCode = "response_read_failed"
		return result
	}
	result.HTTPStatus = resp.StatusCode
	result.Reachable = true
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		result.ErrorCode = "reachable"
	} else {
		result.ErrorCode = "target_reachable_non_success"
	}
	return result
}

func safeNetworkError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	return "connection_failed"
}

// BuildTransport never returns a transport that can silently connect directly
// when proxy setup fails. It is intentionally independent from credential
// health probing and accepts only a validated proxy URL.
func BuildTransport(u *url.URL, timeout time.Duration) (http.RoundTripper, error) {
	if u == nil {
		return nil, errors.New("proxy URL is nil")
	}
	validated, err := Validate(u.String())
	if err != nil {
		return nil, err
	}
	u = validated.URL
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: timeout, ResponseHeaderTimeout: timeout, ExpectContinueTimeout: time.Second, DisableCompression: true, MaxIdleConns: 1, MaxIdleConnsPerHost: 1}
	switch u.Scheme {
	case "http", "https":
		tr.Proxy = http.ProxyURL(u)
	case "socks5h":
		auth := (*xproxy.Auth)(nil)
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &xproxy.Auth{User: u.User.Username(), Password: password}
		}
		dial, err := xproxy.SOCKS5("tcp", u.Host, auth, dialer)
		if err != nil {
			return nil, fmt.Errorf("create socks proxy: %w", err)
		}
		tr.Proxy = nil
		tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			type contextDialer interface {
				DialContext(context.Context, string, string) (net.Conn, error)
			}
			if cd, ok := dial.(contextDialer); ok {
				return cd.DialContext(ctx, network, address)
			}
			return dial.Dial(network, address)
		}
	default:
		return nil, errors.New("unsupported proxy scheme")
	}
	return tr, nil
}
