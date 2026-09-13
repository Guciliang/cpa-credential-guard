// Package quota contains the pure Codex quota classifier and inventory parser.
// It accepts bounded untrusted input and returns only safe summaries.
package quota

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"cpa-credential-guard/internal/domain"
)

const (
	MaxFailureBody   = 128 << 10
	MaxInventoryBody = 256 << 10
	MaxResetFuture   = 365 * 24 * time.Hour
)

type UsageInput struct {
	Provider                 string
	StatusCode               int
	Failed                   bool
	Body                     string
	Headers                  http.Header
	DetectHTTP429            bool
	ClassifyGenericRateLimit bool
	Now                      time.Time
}

// Classify implements the conservative default policy: a 429 needs explicit
// quota evidence unless generic classification is explicitly enabled.
func Classify(in UsageInput) domain.QuotaDecision {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	if !strings.EqualFold(strings.TrimSpace(in.Provider), "codex") || !in.Failed {
		return domain.QuotaDecision{Decision: domain.DecisionIgnore}
	}
	if len(in.Body) > MaxFailureBody {
		return domain.QuotaDecision{Decision: domain.DecisionTransient, Status: in.StatusCode, Reason: "oversized_failure"}
	}
	obj, valid := decodeObject([]byte(in.Body), MaxFailureBody)
	windows, _ := ParseInventory(in.Body, in.Headers, now)
	if len(windows) == 0 {
		windows = headerWindows(in.Headers, now)
	}
	status := in.StatusCode
	if status == 0 && obj != nil {
		status = intValue(obj["status_code"])
	}
	if status == 0 {
		status = intValue(obj["status"])
	}
	if explicitUsageLimit(obj) {
		result := decision(domain.DecisionQuotaExhausted, "codex_usage_limit_reached", status, windows, now)
		result.ResetAt = resetForEvent(obj, windows, in.Headers, now)
		return result
	}
	quotaEvidence := explicitQuotaEvidence(obj, windows)
	// Explicit depletion evidence is authoritative even when an upstream uses a
	// status other than 429. The conservative 429 rule below is specifically
	// about bare/transient rate-limit responses, not about an explicit quota
	// exhaustion signal carried by another status code.
	if quotaEvidence {
		result := decision(domain.DecisionQuotaExhausted, "codex_quota_evidence", status, windows, now)
		result.ResetAt = resetForEvent(obj, windows, in.Headers, now)
		return result
	}
	if status == http.StatusTooManyRequests && in.DetectHTTP429 {
		if quotaEvidence {
			result := decision(domain.DecisionQuotaExhausted, "codex_quota_evidence", status, windows, now)
			result.ResetAt = resetForEvent(obj, windows, in.Headers, now)
			return result
		}
		if in.ClassifyGenericRateLimit && rateLimitSignal(obj) {
			result := decision(domain.DecisionQuotaExhausted, "codex_generic_rate_limit", status, windows, now)
			result.ResetAt = resetForEvent(obj, windows, in.Headers, now)
			return result
		}
		return domain.QuotaDecision{Decision: domain.DecisionTransient, Status: status, Reason: "bare_429"}
	}
	if in.ClassifyGenericRateLimit && rateLimitSignal(obj) && (status != http.StatusTooManyRequests || in.DetectHTTP429) {
		result := decision(domain.DecisionQuotaExhausted, "codex_generic_rate_limit", status, windows, now)
		result.ResetAt = resetForEvent(obj, windows, in.Headers, now)
		return result
	}
	if !valid && strings.TrimSpace(in.Body) != "" {
		return domain.QuotaDecision{Decision: domain.DecisionTransient, Status: status, Reason: "invalid_failure"}
	}
	return domain.QuotaDecision{Decision: domain.DecisionTransient, Status: status, Reason: "non_quota_failure"}
}

func decision(kind, reason string, status int, windows []domain.QuotaWindow, now time.Time) domain.QuotaDecision {
	windows = domain.SafeQuotaWindows(windows)
	return domain.QuotaDecision{Decision: kind, Reason: reason, Status: status, Windows: windows, ResetAt: LatestFutureReset(windows, now)}
}

func explicitUsageLimit(obj map[string]any) bool {
	for _, key := range []string{"type", "code", "reason"} {
		if value, ok := findValue(obj, key); ok {
			if text, ok := value.(string); ok && strings.EqualFold(strings.TrimSpace(text), "usage_limit_reached") {
				return true
			}
		}
	}
	return false
}

func rateLimitSignal(obj map[string]any) bool {
	for _, key := range []string{"type", "code", "reason"} {
		if value, ok := findValue(obj, key); ok {
			if text, ok := value.(string); ok {
				v := strings.ToLower(strings.TrimSpace(text))
				if v == "rate_limit_error" || v == "rate_limit_exceeded" || strings.Contains(v, "rate limit") {
					return true
				}
			}
		}
	}
	return false
}

func explicitQuotaEvidence(obj map[string]any, windows []domain.QuotaWindow) bool {
	if boolValue(obj, "limit_reached") || boolValue(obj, "quota_exhausted") || boolValue(obj, "quota_depleted") || boolValue(obj, "no_credits") || boolValue(obj, "noCredits") || boolValue(obj, "is_quota_exhausted") {
		return true
	}
	if value, ok := findValue(obj, "allowed"); ok {
		if b, yes := toBool(value); yes && !b {
			return true
		}
	}
	if value, ok := findValue(obj, "credits_remaining"); ok {
		if remaining, yes := toNumber(value); yes && remaining <= 0 {
			return true
		}
	}
	for _, w := range windows {
		if w.IsExhausted() {
			return true
		}
	}
	for _, value := range stringValues(obj) {
		v := strings.ToLower(value)
		if strings.Contains(v, "no credits") || strings.Contains(v, "no_credits") || strings.Contains(v, "quota exhausted") || strings.Contains(v, "quota_exhausted") || strings.Contains(v, "quota depleted") || strings.Contains(v, "insufficient_quota") {
			return true
		}
	}
	return false
}

// InventoryResult is the parser result used by recovery health checks.
type InventoryResult struct {
	Recognized bool
	Windows    []domain.QuotaWindow
	ResetAt    time.Time
	Error      string
}

// ParseInventory parses the CPAMP-shaped rate_limit inventory plus safe Codex
// headers. It is independent code; it does not retain the response body.
func ParseInventory(body string, headers http.Header, now time.Time) ([]domain.QuotaWindow, bool) {
	result := parseInventory(body, headers, now)
	return domain.SafeQuotaWindows(result.Windows), result.Recognized
}

// ResponseStatus returns an optional upstream status embedded in the CPAMP
// response envelope. The HTTP status remains authoritative when present, but
// this field lets the health adapter fail closed when a gateway wraps a 401 or
// 429 inside an otherwise successful HTTP response.
func ResponseStatus(body []byte) int {
	obj, ok := decodeObject(body, MaxInventoryBody)
	if !ok {
		return 0
	}
	statusFrom := func(value map[string]any) int {
		for _, key := range []string{"status_code", "statusCode", "http_status", "httpStatus"} {
			if candidate, found := value[key]; found {
				status := intValue(candidate)
				if status >= 100 && status <= 599 {
					return status
				}
			}
		}
		return 0
	}
	if status := statusFrom(obj); status != 0 {
		return status
	}
	if nested, ok := obj["body"].(map[string]any); ok {
		return statusFrom(nested)
	}
	return 0
}

func ParseInventoryResponse(body []byte, headers http.Header, now time.Time) (int, []domain.QuotaWindow, bool) {
	status := ResponseStatus(body)
	windows, recognized := ParseInventory(string(body), headers, now)
	return status, windows, recognized
}

func parseInventory(body string, headers http.Header, now time.Time) InventoryResult {
	if len(body) > MaxInventoryBody {
		return InventoryResult{Error: "body_too_large"}
	}
	if now.IsZero() {
		now = time.Now()
	}
	decoded, ok := decodeObject([]byte(body), MaxInventoryBody)
	if !ok {
		return InventoryResult{Error: "invalid_json"}
	}
	windows := make([]domain.QuotaWindow, 0, 4)
	collectWindows(decoded, "", false, nil, now, &windows)
	mergeHeaderWindows(&windows, headerWindows(headers, now))
	// CPAMP considers an explicitly present rate-limit family an observed
	// inventory even when its windows are empty. A successful health response
	// therefore needs a recognized family, not necessarily a non-empty window.
	recognized := recognizedInventoryShape(decoded)
	if !recognized {
		return InventoryResult{Recognized: false, Error: "missing_inventory"}
	}
	if reset := headerReset(headers, now); !reset.IsZero() {
		for index := range windows {
			if windows[index].Blocking && windows[index].ResetAt.IsZero() {
				windows[index].ResetAt = reset
			}
		}
	}
	return InventoryResult{Recognized: true, Windows: windows, ResetAt: LatestFutureReset(windows, now)}
}

func headerWindows(headers http.Header, now time.Time) []domain.QuotaWindow {
	if headers == nil {
		return nil
	}
	type headerWindow struct {
		used    *float64
		limit   *bool
		allowed *bool
		reset   time.Time
	}
	byFamily := make(map[string]*headerWindow)
	for name, values := range headers {
		lower := strings.ToLower(strings.TrimSpace(name))
		if !strings.HasPrefix(lower, "x-codex-") || len(values) == 0 {
			continue
		}
		suffixes := []struct{ suffix, kind string }{
			{"-used-percent", "used"},
			{"-limit-reached", "limit"},
			{"-allowed", "allowed"},
			{"-reset-after-seconds", "after"},
			{"-reset-at", "at"},
		}
		for _, candidate := range suffixes {
			if !strings.HasSuffix(lower, candidate.suffix) {
				continue
			}
			family := safeFamily(strings.TrimSuffix(strings.TrimPrefix(lower, "x-codex-"), candidate.suffix))
			if family == "quota" {
				continue
			}
			entry := byFamily[family]
			if entry == nil {
				entry = &headerWindow{}
				byFamily[family] = entry
			}
			raw := strings.TrimSpace(values[0])
			switch candidate.kind {
			case "used":
				if value, err := strconv.ParseFloat(raw, 64); err == nil && value >= 0 && value <= 1000 && !math.IsNaN(value) && !math.IsInf(value, 0) {
					entry.used = &value
				}
			case "limit":
				if value, err := strconv.ParseBool(raw); err == nil {
					entry.limit = &value
				}
			case "allowed":
				if value, err := strconv.ParseBool(raw); err == nil {
					entry.allowed = &value
				}
			case "after":
				if seconds, valid := finiteSeconds(raw); valid {
					reset := now.Add(time.Duration(seconds * float64(time.Second)))
					if validReset(reset, now) {
						entry.reset = reset
					}
				}
			case "at":
				if reset, valid := parseTime(raw, now); valid {
					entry.reset = reset
				}
			}
		}
	}
	windows := make([]domain.QuotaWindow, 0, len(byFamily))
	for family, entry := range byFamily {
		if entry.used == nil && entry.limit == nil && entry.allowed == nil && entry.reset.IsZero() {
			continue
		}
		window := domain.QuotaWindow{Family: family, ResetAt: entry.reset}
		if entry.used != nil {
			value := *entry.used
			window.UsedPercent = &value
		}
		if entry.limit != nil {
			window.LimitReached = *entry.limit
		}
		if entry.allowed != nil {
			value := *entry.allowed
			window.Allowed = &value
		}
		window.Blocking = window.IsExhausted()
		windows = append(windows, window)
	}
	return windows
}

func mergeHeaderWindows(windows *[]domain.QuotaWindow, headers []domain.QuotaWindow) {
	for _, header := range headers {
		matched := false
		for index := range *windows {
			if (*windows)[index].Family != header.Family {
				continue
			}
			matched = true
			window := &(*windows)[index]
			if window.UsedPercent == nil && header.UsedPercent != nil {
				value := *header.UsedPercent
				window.UsedPercent = &value
			}
			if !window.LimitReached && header.LimitReached {
				window.LimitReached = true
			}
			if window.Allowed == nil && header.Allowed != nil {
				value := *header.Allowed
				window.Allowed = &value
			}
			if window.ResetAt.IsZero() && !header.ResetAt.IsZero() {
				window.ResetAt = header.ResetAt
			}
			window.Blocking = window.IsExhausted()
		}
		if !matched {
			*windows = append(*windows, header)
		}
	}
}
func collectWindows(value any, path string, inheritedLimit bool, inheritedAllowed *bool, now time.Time, out *[]domain.QuotaWindow) {
	switch typed := value.(type) {
	case []any:
		for index, child := range typed {
			collectWindows(child, fmt.Sprintf("%s.%d", path, index), inheritedLimit, inheritedAllowed, now, out)
		}
		return
	case []map[string]any:
		for index, child := range typed {
			collectWindows(child, fmt.Sprintf("%s.%d", path, index), inheritedLimit, inheritedAllowed, now, out)
		}
		return
	}
	m, ok := value.(map[string]any)
	if !ok {
		return
	}
	localLimit, hasLocalLimit := boolField(m, "limit_reached", "limitReached", "exhausted")
	localAllowed, hasLocalAllowed := boolField(m, "allowed")
	effectiveLimit := inheritedLimit || (hasLocalLimit && localLimit)
	effectiveAllowed := inheritedAllowed
	if hasLocalAllowed && !localAllowed {
		blocked := false
		effectiveAllowed = &blocked
	}
	lowerPath := strings.ToLower(path)
	isCandidate := strings.Contains(lowerPath, "window") || strings.HasSuffix(lowerPath, "rate_limit") || strings.HasSuffix(lowerPath, "rate_limits")
	if isCandidate {
		if w, ok := parseWindow(m, familyName(path), now); ok {
			if effectiveLimit {
				w.LimitReached = true
			}
			if effectiveAllowed != nil && !*effectiveAllowed {
				blocked := false
				w.Allowed = &blocked
			}
			w.Blocking = w.IsExhausted()
			*out = append(*out, w)
		}
	}
	for key, child := range m {
		childPath := key
		if path != "" {
			childPath = path + "." + key
		}
		collectWindows(child, childPath, effectiveLimit, effectiveAllowed, now, out)
	}
}

func recognizedInventoryShape(m map[string]any) bool {
	for _, key := range []string{"rate_limit", "rateLimit", "code_review_rate_limit", "codeReviewRateLimit"} {
		value, ok := m[key]
		if !ok {
			if body, bodyOK := m["body"].(map[string]any); bodyOK {
				value, ok = body[key]
			}
		}
		if ok {
			if _, valid := value.(map[string]any); valid {
				return true
			}
		}
	}
	for _, key := range []string{"additional_rate_limits", "additionalRateLimits"} {
		value, ok := m[key]
		if !ok {
			if body, bodyOK := m["body"].(map[string]any); bodyOK {
				value, ok = body[key]
			}
		}
		if ok {
			switch value.(type) {
			case []any, []map[string]any:
				return true
			}
		}
	}
	if body, ok := m["body"].(map[string]any); ok && body != nil {
		return recognizedInventoryShape(body)
	}
	return false
}

func parseWindow(m map[string]any, family string, now time.Time) (domain.QuotaWindow, bool) {
	used, hasUsed := numberField(m, "used_percent", "usedPercent", "used_percentage")
	limit, hasLimit := boolField(m, "limit_reached", "limitReached", "exhausted")
	allowed, hasAllowed := boolField(m, "allowed")
	seconds, hasSeconds := numberField(m, "limit_window_seconds", "window_seconds", "windowSeconds", "duration_seconds")
	reset := time.Time{}
	// Structured absolute and relative values have precedence over headers and
	// Retry-After; this function only handles structured fields.
	for _, key := range []string{"resets_at", "reset_at", "resetsAt", "resetAt", "reset_time", "resetTime"} {
		if value, ok := m[key]; ok {
			if t, valid := parseTimeValue(value, now); valid {
				reset = t
				break
			}
		}
	}
	if reset.IsZero() {
		for _, key := range []string{"resets_in_seconds", "reset_after_seconds", "resetsInSeconds", "resetAfterSeconds"} {
			if value, ok := m[key]; ok {
				if n, valid := finiteSeconds(value); valid {
					t := now.Add(time.Duration(n * float64(time.Second)))
					if validReset(t, now) {
						reset = t
						break
					}
				}
			}
		}
	}
	if !hasUsed && !hasLimit && !hasAllowed && !hasSeconds && reset.IsZero() {
		return domain.QuotaWindow{}, false
	}
	w := domain.QuotaWindow{Family: safeFamily(family), ResetAt: reset}
	if hasUsed {
		w.UsedPercent = &used
	}
	if hasLimit {
		w.LimitReached = limit
	}
	if hasAllowed {
		w.Allowed = &allowed
	}
	if hasSeconds && seconds >= 0 && seconds <= math.MaxInt64 {
		w.WindowSeconds = int64(seconds)
	}
	w.Blocking = w.IsExhausted()
	return w, true
}

func LatestFutureReset(windows []domain.QuotaWindow, now time.Time) time.Time {
	if now.IsZero() {
		now = time.Now()
	}
	latest := time.Time{}
	for _, w := range windows {
		if w.ResetAt.After(now) && validReset(w.ResetAt, now) && w.Blocking && w.ResetAt.After(latest) {
			latest = w.ResetAt
		}
	}
	return latest
}

func resetForEvent(obj map[string]any, windows []domain.QuotaWindow, headers http.Header, now time.Time) time.Time {
	// Structured fields win over headers and Retry-After, regardless of which
	// response object carries them. Among exhausted windows, the latest usable
	// reset in the winning structured class is selected.
	if reset := structuredReset(obj, now); !reset.IsZero() {
		return reset
	}
	if reset := LatestFutureReset(windows, now); !reset.IsZero() {
		return reset
	}
	return headerReset(headers, now)
}

func structuredReset(obj map[string]any, now time.Time) time.Time {
	if obj == nil {
		return time.Time{}
	}
	absolute := make([]time.Time, 0, 2)
	relative := make([]time.Time, 0, 2)
	var walk func(any, string, bool, *bool)
	walk = func(value any, path string, inheritedLimit bool, inheritedAllowed *bool) {
		switch typed := value.(type) {
		case map[string]any:
			localLimit, hasLocalLimit := boolField(typed, "limit_reached", "limitReached", "exhausted")
			localAllowed, hasLocalAllowed := boolField(typed, "allowed")
			effectiveLimit := inheritedLimit || (hasLocalLimit && localLimit)
			effectiveAllowed := inheritedAllowed
			if hasLocalAllowed && !localAllowed {
				blocked := false
				effectiveAllowed = &blocked
			}

			lowerPath := strings.ToLower(path)
			isCandidate := strings.Contains(lowerPath, "window") || strings.HasSuffix(lowerPath, "rate_limit") || strings.HasSuffix(lowerPath, "rate_limits")
			candidateParsed := false
			candidateBlocking := true
			if isCandidate {
				if window, ok := parseWindow(typed, familyName(path), now); ok {
					candidateParsed = true
					if effectiveLimit {
						window.LimitReached = true
					}
					if effectiveAllowed != nil && !*effectiveAllowed {
						blocked := false
						window.Allowed = &blocked
					}
					candidateBlocking = window.IsExhausted()
				}
			}

			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := typed[key]
				includeReset := !isCandidate || !candidateParsed || candidateBlocking
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "resets_at", "reset_at", "resetsat", "resetat", "reset_time", "resetime":
					if includeReset {
						if reset, valid := parseTimeValue(child, now); valid {
							absolute = append(absolute, reset)
						}
					}
				case "resets_in_seconds", "reset_after_seconds", "resetsinseconds", "resetafterseconds":
					if includeReset {
						if seconds, valid := finiteSeconds(child); valid {
							reset := now.Add(time.Duration(seconds * float64(time.Second)))
							if validReset(reset, now) {
								relative = append(relative, reset)
							}
						}
					}
				}
				childPath := key
				if path != "" {
					childPath = path + "." + key
				}
				walk(child, childPath, effectiveLimit, effectiveAllowed)
			}
		case []any:
			for index, child := range typed {
				walk(child, fmt.Sprintf("%s.%d", path, index), inheritedLimit, inheritedAllowed)
			}
		}
	}
	walk(obj, "", false, nil)
	latest := func(values []time.Time) time.Time {
		result := time.Time{}
		for _, value := range values {
			if value.After(result) {
				result = value
			}
		}
		return result
	}
	if reset := latest(absolute); !reset.IsZero() {
		return reset
	}
	return latest(relative)
}

func headerReset(headers http.Header, now time.Time) time.Time {
	if headers == nil {
		return time.Time{}
	}
	codexLatest := time.Time{}
	retryLatest := time.Time{}
	for name, values := range headers {
		lower := strings.ToLower(name)
		for _, raw := range values {
			if strings.HasPrefix(lower, "x-codex-") && strings.HasSuffix(lower, "reset-at") {
				if t, valid := parseTime(raw, now); valid && t.After(codexLatest) {
					codexLatest = t
				}
			}
			if strings.HasPrefix(lower, "x-codex-") && strings.HasSuffix(lower, "reset-after-seconds") {
				if n, valid := finiteSeconds(raw); valid {
					t := now.Add(time.Duration(n * float64(time.Second)))
					if validReset(t, now) && t.After(codexLatest) {
						codexLatest = t
					}
				}
			}
			if lower == "retry-after" {
				if t, valid := parseTime(raw, now); valid && t.After(retryLatest) {
					retryLatest = t
				}
			}
		}
	}
	// Codex reset metadata is more specific than Retry-After. Do not let a
	// generic gateway retry hint extend an otherwise precise quota reset.
	if !codexLatest.IsZero() {
		return codexLatest
	}
	return retryLatest
}

func validReset(t, now time.Time) bool { return t.After(now) && !t.After(now.Add(MaxResetFuture)) }

func parseTimeValue(v any, now time.Time) (time.Time, bool) {
	switch value := v.(type) {
	case string:
		return parseTime(value, now)
	case float64:
		if value > 1e9 && value < 1e11 {
			return parseTime(fmt.Sprintf("%d", int64(value)), now)
		}
		if value >= 0 && value <= MaxResetFuture.Seconds() {
			t := now.Add(time.Duration(value * float64(time.Second)))
			return t, validReset(t, now)
		}
	case json.Number:
		return parseTimeValue(value.String(), now)
	}
	return time.Time{}, false
}

func parseTime(value string, now time.Time) (time.Time, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, false
	}
	if n, err := strconv.ParseInt(value, 10, 64); err == nil {
		var t time.Time
		if n > 1e12 {
			// Treat large numeric values as Unix milliseconds, but reject them
			// before multiplying so an overflowing timestamp cannot wrap into a
			// plausible future reset.
			maxMillis := now.Add(MaxResetFuture).UnixMilli()
			if n > maxMillis {
				return time.Time{}, false
			}
			t = time.UnixMilli(n).UTC()
		} else if n > 1e9 {
			t = time.Unix(n, 0).UTC()
		} else if n >= 0 {
			t = now.Add(time.Duration(n) * time.Second)
		}
		if validReset(t, now) {
			return t, true
		}
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, value); err == nil && validReset(t, now) {
		return t.UTC(), true
	}
	if t, err := http.ParseTime(value); err == nil && validReset(t, now) {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func finiteSeconds(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		if n >= 0 && n <= MaxResetFuture.Seconds() && !math.IsNaN(n) && !math.IsInf(n, 0) {
			return n, true
		}
	case json.Number:
		f, err := n.Float64()
		if err == nil {
			return finiteSeconds(f)
		}
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		if err == nil {
			return finiteSeconds(f)
		}
	}
	return 0, false
}

func decodeObject(raw []byte, limit int) (map[string]any, bool) {
	if len(raw) == 0 || len(raw) > limit {
		return nil, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return nil, false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, false
	}
	m, ok := value.(map[string]any)
	return m, ok
}

func findValue(m map[string]any, wanted string) (any, bool) {
	for key, value := range m {
		if strings.EqualFold(key, wanted) {
			return value, true
		}
		if child, ok := value.(map[string]any); ok {
			if found, yes := findValue(child, wanted); yes {
				return found, true
			}
		}
	}
	return nil, false
}

func boolValue(m map[string]any, wanted string) bool {
	value, ok := findValue(m, wanted)
	if !ok {
		return false
	}
	b, _ := toBool(value)
	return b
}
func boolField(m map[string]any, keys ...string) (bool, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			b, yes := toBool(v)
			return b, yes
		}
	}
	return false, false
}
func numberField(m map[string]any, keys ...string) (float64, bool) {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if n, yes := toNumber(v); yes {
				return n, true
			}
		}
	}
	return 0, false
}
func toBool(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(x))
		return b, err == nil
	}
	return false, false
}
func toNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case json.Number:
		f, err := x.Float64()
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil && !math.IsNaN(f) && !math.IsInf(f, 0)
	}
	return 0, false
}
func intValue(v any) int {
	n, ok := toNumber(v)
	if !ok || n < 0 || n > math.MaxInt32 {
		return 0
	}
	return int(n)
}

func stringValues(m map[string]any) []string {
	out := make([]string, 0, 8)
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case map[string]any:
			for _, child := range x {
				walk(child)
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(m)
	return out
}

func familyName(path string) string {
	if path == "" {
		return "quota"
	}
	parts := strings.Split(path, ".")
	last := parts[len(parts)-1]
	last = strings.TrimSuffix(strings.TrimSuffix(last, "_window"), "Window")
	if last == "" {
		return "quota"
	}
	return last
}
func safeFamily(value string) string {
	return domain.SafeFamily(value)
}
