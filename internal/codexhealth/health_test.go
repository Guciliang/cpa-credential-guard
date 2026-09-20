package codexhealth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"cpa-credential-guard/internal/domain"
)

func TestParseResponseRequiresCompleteInventoryAndNeverReturnsSecrets(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	headers := http.Header{}
	valid := []byte(`{"status_code":200,"body":{"rate_limit":{"primary_window":{"used_percent":20},"secondary_window":{"used_percent":10}}}}`)
	got := ParseResponse(200, headers, valid, now)
	if got.Status != domain.ProbeSuccess || len(got.Windows) != 2 {
		t.Fatalf("summary=%#v", got)
	}
	exhausted := ParseResponse(200, headers, []byte(`{"body":{"rate_limit":{"primary_window":{"used_percent":100}}}}`), now)
	if exhausted.Status != domain.ProbeExhausted || exhausted.SafeError != "quota_exhausted" {
		t.Fatalf("summary=%#v", exhausted)
	}
	for _, body := range [][]byte{[]byte(`{"body":{"status":"ok"}}`), []byte(`{"body":{"rate_limit":"changed"}}`)} {
		ambiguous := ParseResponse(200, headers, body, now)
		if ambiguous.Status != domain.ProbeAmbiguous {
			t.Fatalf("summary=%#v", ambiguous)
		}
	}
}

func TestParseResponseHonorsEnvelopeStatus(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := []byte(`{"status_code":401,"body":{"rate_limit":{}}}`)
	got := ParseResponse(http.StatusOK, nil, body, now)
	if got.Status != domain.ProbeError || got.SafeError != "auth_failed" || got.HTTPStatus != http.StatusUnauthorized {
		t.Fatalf("summary=%#v", got)
	}
	unknown := ParseResponse(0, nil, []byte(`{"status_code":200,"body":{"rate_limit":{}}}`), now)
	if unknown.Status != domain.ProbeAmbiguous || unknown.SafeError != "invalid_inventory" || unknown.HTTPStatus != http.StatusOK {
		t.Fatalf("zero transport status summary=%#v", unknown)
	}
}

func TestProbeDoesNotTreatGenericTokenFieldAsAccessToken(t *testing.T) {
	called := false
	client := NewClient()
	client.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	summary, err := client.Probe(context.Background(), []byte(`{"token":"should-not-be-used"}`))
	if err != nil {
		t.Fatal(err)
	}
	if called || summary.SafeError != "missing_access_token" {
		t.Fatalf("called=%v summary=%#v", called, summary)
	}
}

func TestProbeExtractsTransientTokenOnly(t *testing.T) {
	client := NewClient()
	client.RoundTripper = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != UsageURL {
			t.Fatalf("url=%s", req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer transient-token" {
			t.Fatalf("authorization=%q", req.Header.Get("Authorization"))
		}
		if req.Header.Get("ChatGPT-Account-ID") != "account" {
			t.Fatalf("account=%q", req.Header.Get("ChatGPT-Account-ID"))
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
	})
	summary, err := client.Probe(context.Background(), []byte(`{"access_token":"transient-token","account_id":"account"}`))
	if err != nil {
		t.Fatal(err)
	}
	if summary.Status != domain.ProbeAmbiguous || summary.SafeError != "invalid_inventory" {
		t.Fatalf("summary=%#v", summary)
	}
}

func TestWakeUsesFixedRequestAndAcceptsOnlyCompletedProtocol(t *testing.T) {
	client := NewClient()
	client.RoundTripper = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.String() != WakeURL {
			t.Fatalf("request=%s %s", req.Method, req.URL)
		}
		if req.Header.Get("Authorization") != "Bearer transient-token" || req.Header.Get("Cookie") != "" {
			t.Fatalf("headers contain unsafe values: authorization=%q cookie=%q", req.Header.Get("Authorization"), req.Header.Get("Cookie"))
		}
		body, err := io.ReadAll(req.Body)
		if err != nil {
			t.Fatal(err)
		}
		for _, marker := range []string{`"model":"gpt-5.6-luna"`, `"effort":"low"`, `"text":"Hello"`} {
			if !strings.Contains(string(body), marker) {
				t.Fatalf("request body missing %s", marker)
			}
		}
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: io.NopCloser(strings.NewReader("data: {\"type\":\"response.completed\"}\n\n"))}, nil
	})
	result, err := client.Wake(context.Background(), []byte(`{"access_token":"transient-token","account_id":"account"}`), WakeModel, "low")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Completed || result.ErrorCode != "wake_success" {
		t.Fatalf("result=%#v", result)
	}
	if strings.Contains(result.ErrorCode, "transient-token") {
		t.Fatal("token leaked into result")
	}
}

func TestWakeRejectsIncompleteOrUnsafeResponses(t *testing.T) {
	client := NewClient()
	client.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"status":"in_progress","error":"raw secret"}`))}, nil
	})
	result, err := client.Wake(context.Background(), []byte(`{"access_token":"transient-token"}`), WakeModel, "low")
	if err != nil {
		t.Fatal(err)
	}
	if result.Completed || result.ErrorCode != "wake_protocol_failed" {
		t.Fatalf("result=%#v", result)
	}
	unauthorized := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody}, nil
	})
	client.RoundTripper = unauthorized
	result, err = client.Wake(context.Background(), []byte(`{"access_token":"transient-token"}`), WakeModel, "low")
	if err != nil {
		t.Fatal(err)
	}
	if result.ErrorCode != "wake_auth_failed" {
		t.Fatalf("result=%#v", result)
	}
}

func TestWakeRequiresNonEmptyResponsesOutputStructure(t *testing.T) {
	responses := []struct {
		name  string
		body  string
		valid bool
	}{
		{name: "output null", body: `{"id":"resp_1","status":"completed","output":null}`},
		{name: "empty object", body: `{"id":"resp_1","status":"completed","output":{}}`},
		{name: "missing output", body: `{"id":"resp_1","status":"completed"}`},
		{name: "empty output", body: `{"id":"resp_1","status":"completed","output":[]}`},
		{name: "invalid item", body: `{"id":"resp_1","status":"completed","output":[{}]}`},
		{name: "valid message", body: `{"id":"resp_1","status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"Hello"}]}]}`, valid: true},
		{name: "valid output text compatibility", body: `{"id":"resp_1","status":"completed","output_text":"Hello"}`, valid: true},
	}
	client := NewClient()
	for _, test := range responses {
		t.Run(test.name, func(t *testing.T) {
			client.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})
			result, err := client.Wake(context.Background(), []byte(`{"access_token":"transient-token"}`), WakeModel, "low")
			if err != nil {
				t.Fatal(err)
			}
			if result.Completed != test.valid || (!test.valid && result.ErrorCode != "wake_protocol_failed") || (test.valid && result.ErrorCode != "wake_success") {
				t.Fatalf("body=%s result=%#v", test.body, result)
			}
		})
	}
}

func TestProbeRejectsOversizedCredentialHeaderWithoutRequest(t *testing.T) {
	called := false
	client := NewClient()
	client.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	oversized := strings.Repeat("x", maxCredentialHeaderValue+1)
	summary, err := client.Probe(context.Background(), []byte(`{"access_token":"`+oversized+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	if called || summary.SafeError != "missing_access_token" {
		t.Fatalf("called=%v summary=%#v", called, summary)
	}
}

func TestProbeRejectsMalformedProxyFieldWithoutRequest(t *testing.T) {
	called := false
	client := NewClient()
	client.RoundTripper = roundTripFunc(func(*http.Request) (*http.Response, error) {
		called = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})
	summary, err := client.Probe(context.Background(), []byte(`{"access_token":"transient-token","proxy_url":123}`))
	if err != nil {
		t.Fatal(err)
	}
	if called || summary.Status != domain.ProbeError || summary.SafeError != "proxy_setup_failed" {
		t.Fatalf("called=%v summary=%#v", called, summary)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
