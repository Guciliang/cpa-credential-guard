package quota

import (
	"net/http"
	"testing"
	"time"

	"cpa-credential-guard/internal/domain"
)

func TestClassifyConservative429Policy(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name, provider, body string
		status               int
		generic              bool
		want                 string
	}{
		{"bare", "codex", `{"error":{"type":"rate_limit_error"}}`, 429, false, domain.DecisionTransient},
		{"usage limit", "codex", `{"error":{"type":"usage_limit_reached"}}`, 429, false, domain.DecisionQuotaExhausted},
		{"message only", "codex", `{"message":"usage_limit_reached"}`, 429, false, domain.DecisionTransient},
		{"limit reached", "codex", `{"error":{"limit_reached":true}}`, 429, false, domain.DecisionQuotaExhausted},
		{"allowed false", "codex", `{"rate_limit":{"allowed":false}}`, 429, false, domain.DecisionQuotaExhausted},
		{"used exhausted", "codex", `{"rate_limit":{"primary_window":{"used_percent":100}}}`, 429, false, domain.DecisionQuotaExhausted},
		{"generic opt in", "codex", `{"error":{"type":"rate_limit_exceeded"}}`, 429, true, domain.DecisionQuotaExhausted},
		{"other provider", "claude", `{"error":{"type":"usage_limit_reached"}}`, 429, true, domain.DecisionIgnore},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(UsageInput{Provider: tt.provider, StatusCode: tt.status, Failed: true, Body: tt.body, DetectHTTP429: true, ClassifyGenericRateLimit: tt.generic, Now: now})
			if got.Decision != tt.want {
				t.Fatalf("decision=%#v", got)
			}
		})
	}
}

func TestRetryAfterAloneDoesNotClassifyBare429(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := Classify(UsageInput{Provider: "codex", StatusCode: 429, Failed: true, Body: `{"error":{"type":"rate_limit_error"}}`, Headers: http.Header{"Retry-After": []string{"60"}}, DetectHTTP429: true, Now: now})
	if got.Decision != domain.DecisionTransient {
		t.Fatalf("decision=%#v", got)
	}
}

func TestCodexResetHeaderTakesPrecedenceOverRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	codexReset := now.Add(30 * time.Minute)
	got := Classify(UsageInput{
		Provider:      "codex",
		StatusCode:    http.StatusTooManyRequests,
		Failed:        true,
		Body:          `{"error":{"type":"usage_limit_reached"}}`,
		Headers:       http.Header{"X-Codex-Primary-Reset-At": []string{codexReset.Format(time.RFC3339)}, "Retry-After": []string{"3600"}},
		DetectHTTP429: true,
		Now:           now,
	})
	if got.Decision != domain.DecisionQuotaExhausted || !got.ResetAt.Equal(codexReset) {
		t.Fatalf("decision=%#v want reset=%s", got, codexReset)
	}
}

func TestRetryAfterIsUsedWhenCodexResetHeaderIsAbsent(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := Classify(UsageInput{
		Provider:      "codex",
		StatusCode:    http.StatusTooManyRequests,
		Failed:        true,
		Body:          `{"error":{"type":"usage_limit_reached"}}`,
		Headers:       http.Header{"Retry-After": []string{"60"}},
		DetectHTTP429: true,
		Now:           now,
	})
	if got.Decision != domain.DecisionQuotaExhausted || !got.ResetAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("decision=%#v", got)
	}
}

func TestOverflowingMillisecondResetIsIgnored(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	windows, _ := ParseInventory(`{"rate_limit":{"primary_window":{"used_percent":100,"reset_at":"9223372036854775807"}}}`, nil, now)
	if len(windows) != 1 || !windows[0].ResetAt.IsZero() {
		t.Fatalf("windows=%#v", windows)
	}
}

func TestExplicitQuotaEvidenceIsNotLimitedTo429(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := Classify(UsageInput{Provider: "codex", StatusCode: 403, Failed: true, Body: `{"error":{"limit_reached":true}}`, DetectHTTP429: true, Now: now})
	if got.Decision != domain.DecisionQuotaExhausted {
		t.Fatalf("decision=%#v", got)
	}
}

func TestResponseStatusReadsCPAMPEnvelope(t *testing.T) {
	if got := ResponseStatus([]byte(`{"status_code":429,"body":{}}`)); got != 429 {
		t.Fatalf("status=%d", got)
	}
	if got := ResponseStatus([]byte(`{"body":{"status_code":500}}`)); got != 500 {
		t.Fatalf("nested status=%d", got)
	}
}

func TestTrailingJSONIsRejected(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := `{"error":{"type":"usage_limit_reached"}} trailing`
	if got := ResponseStatus([]byte(body)); got != 0 {
		t.Fatalf("status=%d", got)
	}
	if _, recognized := ParseInventory(body, nil, now); recognized {
		t.Fatal("trailing JSON should not be recognized")
	}
	got := Classify(UsageInput{Provider: "codex", StatusCode: http.StatusTooManyRequests, Failed: true, Body: body, DetectHTTP429: true, Now: now})
	if got.Decision != domain.DecisionTransient {
		t.Fatalf("decision=%#v", got)
	}
}

func TestStructuredEventResetIsUsedWhenNoInventoryWindowExists(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	got := Classify(UsageInput{Provider: "codex", StatusCode: http.StatusTooManyRequests, Failed: true, Body: `{"error":{"type":"usage_limit_reached","resets_at":"2026-01-01T01:00:00Z"}}`, Headers: http.Header{"Retry-After": []string{"3600"}}, DetectHTTP429: true, Now: now})
	want := now.Add(time.Hour)
	if got.Decision != domain.DecisionQuotaExhausted || !got.ResetAt.Equal(want) {
		t.Fatalf("decision=%#v want reset=%s", got, want)
	}
}
func TestResetPrecedenceAndLatestBlockingWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := `{"body":{"rate_limit":{"primary_window":{"used_percent":100,"resets_in_seconds":60,"reset_at":"2026-01-01T00:10:00Z"},"secondary_window":{"used_percent":100,"resets_in_seconds":120,"reset_at":"2026-01-01T00:20:00Z"}}}}`
	headers := http.Header{"X-Codex-Primary-Reset-At": []string{"2026-01-01T00:30:00Z"}, "Retry-After": []string{"3600"}}
	got := Classify(UsageInput{Provider: "codex", StatusCode: 429, Failed: true, Body: body, Headers: headers, DetectHTTP429: true, Now: now})
	if got.Decision != domain.DecisionQuotaExhausted {
		t.Fatalf("decision=%#v", got)
	}
	want := time.Date(2026, 1, 1, 0, 20, 0, 0, time.UTC)
	if !got.ResetAt.Equal(want) {
		t.Fatalf("reset=%s want=%s", got.ResetAt, want)
	}
	if len(got.Windows) != 2 {
		t.Fatalf("windows=%#v", got.Windows)
	}
}

func TestResetIgnoresNonBlockingWindow(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := `{"rate_limit":{"primary_window":{"used_percent":100,"reset_at":"2026-01-01T00:10:00Z"},"secondary_window":{"used_percent":50,"reset_at":"2026-01-01T01:00:00Z"}}}`
	got := Classify(UsageInput{Provider: "codex", StatusCode: http.StatusTooManyRequests, Failed: true, Body: body, DetectHTTP429: true, Now: now})
	want := now.Add(10 * time.Minute)
	if got.Decision != domain.DecisionQuotaExhausted || !got.ResetAt.Equal(want) {
		t.Fatalf("decision=%#v want reset=%s", got, want)
	}
}

func TestParseInventoryCPAMPFamiliesAndEmptyShape(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := `{"status_code":200,"body":{"rate_limit":{"primary_window":{"used_percent":10,"limit_window_seconds":18000},"secondary_window":{"used_percent":20}},"code_review_rate_limit":{"primary_window":{"used_percent":0}},"additional_rate_limits":[]}}`
	windows, recognized := ParseInventory(body, nil, now)
	if !recognized || len(windows) != 3 {
		t.Fatalf("recognized=%v windows=%#v", recognized, windows)
	}
	_, recognized = ParseInventory(`{"status_code":200,"body":{"rate_limit":{}}}`, nil, now)
	if !recognized {
		t.Fatal("empty known inventory should be recognized")
	}
	_, recognized = ParseInventory(`{"status_code":200,"body":{"rate_limit":"changed"}}`, nil, now)
	if recognized {
		t.Fatal("schema changed inventory should be ambiguous")
	}
}

func TestInvalidAndOversizedResetAreIgnored(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	body := `{"rate_limit":{"primary_window":{"used_percent":100,"reset_at":"yesterday"}}}`
	windows, _ := ParseInventory(body, nil, now)
	if len(windows) != 1 || !windows[0].ResetAt.IsZero() {
		t.Fatalf("windows=%#v", windows)
	}
	tooBig := make([]byte, MaxInventoryBody+1)
	for i := range tooBig {
		tooBig[i] = ' '
	}
	if _, ok := ParseInventory(string(tooBig), nil, now); ok {
		t.Fatal("oversized body recognized")
	}
}
