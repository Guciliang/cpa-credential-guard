package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestValidateRedactsUserinfoQueryAndNormalizesSOCKS(t *testing.T) {
	validated, err := Validate("socks5://alice:secret@Proxy.Example:1080/path?password=hidden")
	if err != nil {
		t.Fatal(err)
	}
	if validated.URL.Scheme != "socks5h" {
		t.Fatalf("scheme=%s", validated.URL.Scheme)
	}
	if strings.Contains(validated.Projection.Endpoint, "secret") || strings.Contains(validated.Projection.Endpoint, "alice") || strings.Contains(validated.Projection.Endpoint, "password") {
		t.Fatalf("projection leaked: %#v", validated.Projection)
	}
	if validated.Projection.Endpoint != "socks5h://proxy.example:1080" {
		t.Fatalf("endpoint=%q", validated.Projection.Endpoint)
	}
	if validated.Projection.Remark != "" || validated.Projection.ProfileID != "" {
		t.Fatalf("unexpected profile metadata: %#v", validated.Projection)
	}
	for _, raw := range []string{"ftp://proxy.example:21", "http://proxy.example", "http://proxy.example:abc", "http://proxy.example:8080#fragment", ""} {
		if _, err := Validate(raw); err == nil {
			t.Fatalf("accepted invalid proxy %q", raw)
		}
	}
	for _, raw := range []string{"http://proxy.example:8080/%0A", "http://user%0Aname:pass@proxy.example:8080"} {
		if _, err := Validate(raw); err == nil {
			t.Fatalf("accepted unsafe proxy %q", raw)
		}
	}
}

func TestRedactedEndpointExcludesProxyCredentials(t *testing.T) {
	a := Redact("http://alice:one@proxy.example:8080")
	b := Redact("http://bob:two@proxy.example:8080")
	if a.Endpoint != b.Endpoint {
		t.Fatalf("redacted endpoints differ: %v %v", a, b)
	}
	if strings.Contains(a.Endpoint, "alice") || strings.Contains(b.Endpoint, "two") {
		t.Fatal("userinfo leaked")
	}
}

func TestValidateRejectsOutOfRangePortsAndNilChecker(t *testing.T) {
	for _, raw := range []string{"http://proxy.example:0", "http://proxy.example:65536", "http://proxy.example:-1"} {
		if _, err := Validate(raw); err == nil {
			t.Fatalf("accepted invalid port %q", raw)
		}
	}
	result := (*Checker)(nil).Check(context.Background(), "not-a-proxy")
	if result.ErrorCode == "" {
		t.Fatalf("nil checker returned no result: %#v", result)
	}
}

func TestCheckerNeverFallsBackDirectAndBoundsResponse(t *testing.T) {
	called := false
	checker := &Checker{Timeout: time.Second, RoundTripper: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		called = true
		if req.Header.Get("Authorization") != "" || req.Header.Get("Cookie") != "" {
			t.Fatal("credential headers attached")
		}
		return &http.Response{StatusCode: 204, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	result := checker.Check(context.Background(), "http://user:password@proxy.example:8080")
	if !called || !result.Reachable || result.ErrorCode != "reachable" {
		t.Fatalf("result=%#v called=%v", result, called)
	}
	if strings.Contains(result.Projection.Endpoint, "password") {
		t.Fatal("password leaked")
	}
	bad := (&Checker{Timeout: time.Second}).Check(context.Background(), "not-a-proxy")
	if bad.ErrorCode != "invalid_proxy" {
		t.Fatalf("bad=%#v", bad)
	}
}

func TestCheckerRejectsUnexpectedResponseReadError(t *testing.T) {
	checker := &Checker{Timeout: time.Second, RoundTripper: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusNoContent, Body: unexpectedEOFBody{}, Header: make(http.Header)}, nil
	})}
	result := checker.Check(context.Background(), "http://proxy.example:8080")
	if result.Reachable || result.ErrorCode != "response_read_failed" {
		t.Fatalf("result=%#v", result)
	}
}

type unexpectedEOFBody struct{}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (unexpectedEOFBody) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (unexpectedEOFBody) Close() error             { return nil }

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
