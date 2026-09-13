package codexhealth

import (
	"context"
	"net/http"
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
	valid := ParseResponse(0, nil, []byte(`{"status_code":200,"body":{"rate_limit":{}}}`), now)
	if valid.Status != domain.ProbeSuccess || valid.HTTPStatus != http.StatusOK {
		t.Fatalf("zero transport status summary=%#v", valid)
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
