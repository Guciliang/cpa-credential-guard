// Package domain contains the data contracts shared by Credential Guard's
// persistence, management, and network boundaries.  The types intentionally
// contain projections and safe summaries rather than credential material.
package domain

import (
	"strings"
	"time"
)

const (
	SchemaVersion = 1

	maxQuotaWindows = 32
	maxWakeAttempts = 3

	PhaseOwnedDisabled  = "owned_disabled"
	PhaseRestorePending = "restore_pending_probe"
	PhaseProbePending   = "probe_pending"
	PhaseManualReview   = "manual_review"

	DecisionIgnore         = "ignore"
	DecisionTransient      = "transient"
	DecisionQuotaExhausted = "quota_exhausted"

	ProbeSuccess   = "success"
	ProbeExhausted = "exhausted"
	ProbeAmbiguous = "ambiguous"
	ProbeError     = "error"

	QuotaUnknown   = "unknown"
	QuotaAvailable = "available"
	QuotaExhausted = "exhausted"

	UsageNormal        = "normal_cpa_usage"
	UsageRequestFailed = "request_failed"
	UsageUnknown       = "usage_unknown"

	WakeupInitial = "initial_wakeup"
	WakeupReset   = "reset_wakeup"
)

// QuotaWindow is a safe summary of one quota window.  It never carries a raw
// upstream response or credential value.
type QuotaWindow struct {
	Family        string    `json:"family"`
	UsedPercent   *float64  `json:"used_percent,omitempty"`
	LimitReached  bool      `json:"limit_reached,omitempty"`
	Allowed       *bool     `json:"allowed,omitempty"`
	Blocking      bool      `json:"blocking,omitempty"`
	ResetAt       time.Time `json:"reset_at,omitempty"`
	WindowSeconds int64     `json:"window_seconds,omitempty"`
}

func (w QuotaWindow) IsExhausted() bool {
	if w.LimitReached || (w.Allowed != nil && !*w.Allowed) {
		return true
	}
	return w.UsedPercent != nil && *w.UsedPercent >= 100
}

// SafeCode returns an allow-listed reason/error code suitable for persistence
// and management responses. Unknown values are intentionally collapsed so a
// malformed state file or upstream error cannot become a secret-bearing UI
// projection.
func SafeCode(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	switch value {
	case "codex_usage_limit_reached", "codex_quota_evidence", "codex_generic_rate_limit", "oversized_failure", "bare_429", "invalid_failure", "non_quota_failure", "recovery_error", "host_error", "unverifiable_pending_enable", "disable_revision_unavailable", "post_enable_revision_unavailable", "post_enable_guard_unavailable", "redisable_failed", "redisable_revision_unavailable", "ownership_guard_failed", "probe_unavailable", "probe_error", "missing_access_token", "health_client_unavailable", "proxy_setup_failed", "request_failed", "timeout", "connection_failed", "canceled", "empty_response", "response_read_failed", "response_too_large", "auth_failed", "unexpected_status", "invalid_inventory", "quota_exhausted", "save_failed", "revision_unavailable", "stale_preview", "post_save_mismatch", "unknown_phase", "reachable", "target_rate_limited", "target_challenge", "target_unexpected_status", "target_invalid", "profile_not_found", "quota_probe_disabled", "quota_query_failed", "quota_query_in_progress", "quota_unknown", "codex_credential_not_found", "wake_disabled", "wake_auth_failed", "wake_quota_exhausted", "wake_protocol_failed", "wake_request_failed", "wake_manual_review", "wake_success", "usage_confirmed", "usage_unknown", "target_reachable_non_success":
		return value
	default:
		return "unknown"
	}
}

func SafeProbeSummary(in *ProbeSummary) *ProbeSummary {
	if in == nil {
		return nil
	}
	out := *in
	switch out.Status {
	case ProbeSuccess, ProbeExhausted, ProbeAmbiguous, ProbeError:
	default:
		out.Status = ProbeAmbiguous
	}
	out.SafeError = SafeCode(out.SafeError)
	if out.SafeError == "unknown" {
		// A malformed optional probe record must degrade to a generic safe
		// diagnostic rather than make the whole state document unloadable.
		out.SafeError = "probe_error"
	}
	out.Windows = SafeQuotaWindows(in.Windows)
	return &out
}

// SafeQuotaWindows is the single boundary sanitizer for upstream-derived quota
// family labels. Only the small internal vocabulary crosses persistence or a
// management projection; arbitrary response keys collapse to "additional".
func SafeQuotaWindows(in []QuotaWindow) []QuotaWindow {
	if len(in) > maxQuotaWindows {
		in = in[:maxQuotaWindows]
	}
	out := make([]QuotaWindow, 0, len(in))
	for _, window := range in {
		window.Family = SafeFamily(window.Family)
		if window.UsedPercent != nil {
			value := *window.UsedPercent
			if value < 0 || value > 1000 {
				window.UsedPercent = nil
			} else {
				window.UsedPercent = &value
			}
		}
		if window.Allowed != nil {
			value := *window.Allowed
			window.Allowed = &value
		}
		// Blocking is derived from the allow-listed evidence above. Do not trust
		// a persisted or upstream-provided boolean by itself, otherwise an
		// arbitrary window could become a false reset/wakeup trigger.
		window.Blocking = window.IsExhausted()
		out = append(out, window)
	}
	return out
}

func SafeFamily(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "primary":
		return "primary"
	case "secondary":
		return "secondary"
	case "code_review", "code-review":
		return "code_review"
	default:
		// Upstream family names are untrusted response-derived labels. Keep
		// only a bounded allow-list so they cannot become state/UI exfiltration.
		return "additional"
	}
}

func SafeWakeupRecord(in *WakeupRecord, mode string) *WakeupRecord {
	if in == nil {
		return nil
	}
	out := *in
	originalMode := strings.TrimSpace(out.Mode)
	out.Mode = mode
	switch out.Status {
	case "pending", "success", "failed", "unknown":
	default:
		out.Status = "unknown"
	}
	out.SafeError = SafeCode(out.SafeError)
	if out.SafeError == "unknown" {
		out.SafeError = "wake_manual_review"
	}
	if originalMode != mode || (out.Status == "success" && out.SafeError != "wake_success") || (out.Status == "failed" && out.SafeError == "") {
		// A record stored in the wrong mode, or without a matching safe outcome,
		// must never be allowed to suppress or
		// satisfy the other independent wake-up path. Preserve a visible,
		// non-retryable manual-review marker instead of silently relabeling a
		// reset request as an initial request (or vice versa).
		out.Status = "unknown"
		out.SafeError = "wake_manual_review"
		out.AttemptCount = maxWakeAttempts
	}
	if len(out.IdentityHash) > 128 || len(out.WindowKey) > 256 {
		out.IdentityHash = ""
		out.WindowKey = ""
		out.Status = "unknown"
		out.SafeError = "wake_manual_review"
		out.AttemptCount = maxWakeAttempts
	}
	if out.AttemptCount < 0 {
		out.AttemptCount = 0
	}
	if out.AttemptCount > maxWakeAttempts {
		out.AttemptCount = maxWakeAttempts
	}
	if out.Status == "unknown" {
		out.AttemptCount = maxWakeAttempts
		out.NextAttemptAt = time.Time{}
	}
	return &out
}

func SafeQuotaObservation(in *QuotaObservation) *QuotaObservation {
	if in == nil {
		return nil
	}
	out := *in
	switch out.Status {
	case QuotaUnknown, QuotaAvailable, QuotaExhausted:
	default:
		out.Status = QuotaUnknown
	}
	out.SafeError = SafeCode(out.SafeError)
	if out.SafeError == "unknown" {
		out.SafeError = "quota_unknown"
	}
	out.Windows = SafeQuotaWindows(out.Windows)
	if len(out.IdentityHash) > 128 || len(out.AuthIndex) > 256 {
		out.IdentityHash = ""
		out.Status = QuotaUnknown
	}
	return &out
}

func SafeUsageObservation(in *UsageObservation) *UsageObservation {
	if in == nil {
		return nil
	}
	out := *in
	if out.Status == "unknown" {
		out.Status = UsageUnknown
	}
	if out.Status != UsageNormal && out.Status != UsageRequestFailed && out.Status != UsageUnknown {
		out.Status = UsageUnknown
	}
	if len(out.IdentityHash) > 128 || len(out.AuthIndex) > 256 {
		out.IdentityHash = ""
		out.Status = "unknown"
	}
	return &out
}

func SafeCredentialObservation(in CredentialObservation) (CredentialObservation, bool) {
	out := in
	if strings.TrimSpace(out.AuthIndex) == "" || len(out.AuthIndex) > 256 || strings.TrimSpace(out.IdentityHash) == "" || len(out.IdentityHash) > 128 {
		return CredentialObservation{}, false
	}
	out.LastHealthCheck = SafeProbeSummary(out.LastHealthCheck)
	out.Quota = SafeQuotaObservation(out.Quota)
	if out.Quota != nil && (out.Quota.AuthIndex != out.AuthIndex || out.Quota.IdentityHash != out.IdentityHash) {
		// A nested observation must be bound to the same credential identity as
		// its envelope. Drop only the malformed sub-record so other evidence for
		// this credential, and all unrelated credentials, remain usable.
		out.Quota = nil
	}
	out.InitialWakeup = SafeWakeupRecord(out.InitialWakeup, WakeupInitial)
	if out.InitialWakeup != nil && out.InitialWakeup.IdentityHash != out.IdentityHash {
		out.InitialWakeup = nil
	}
	out.ResetWakeup = SafeWakeupRecord(out.ResetWakeup, WakeupReset)
	if out.ResetWakeup != nil && out.ResetWakeup.IdentityHash != out.IdentityHash {
		out.ResetWakeup = nil
	}
	out.Usage = SafeUsageObservation(out.Usage)
	if out.Usage != nil && (out.Usage.AuthIndex != out.AuthIndex || out.Usage.IdentityHash != out.IdentityHash) {
		out.Usage = nil
	}
	return out, true
}

// QuotaDecision is the result of classifying a completed Codex request.
type QuotaDecision struct {
	Decision string        `json:"decision"`
	Reason   string        `json:"reason,omitempty"`
	Status   int           `json:"status,omitempty"`
	ResetAt  time.Time     `json:"reset_at,omitempty"`
	Windows  []QuotaWindow `json:"windows,omitempty"`
}

// ProbeSummary is safe state/UI output from one health request.
type ProbeSummary struct {
	At         time.Time     `json:"at"`
	Status     string        `json:"status"`
	HTTPStatus int           `json:"http_status,omitempty"`
	LatencyMS  int64         `json:"latency_ms,omitempty"`
	SafeError  string        `json:"safe_error,omitempty"`
	Windows    []QuotaWindow `json:"windows,omitempty"`
}

// OwnershipRecord is the minimum durable metadata needed to prove that a
// plugin-owned disabled field can be restored.  It deliberately has no raw
// credential, token, cookie, authorization value, or proxy URL fields.
type OwnershipRecord struct {
	AuthIndex                     string            `json:"auth_index"`
	AuthID                        string            `json:"auth_id,omitempty"`
	FileName                      string            `json:"file_name"`
	DisabledAt                    time.Time         `json:"disabled_at"`
	WasEnabled                    bool              `json:"was_enabled"`
	ContentHashWithoutDisabled    string            `json:"content_hash_without_disabled"`
	PluginSaveHostRevision        string            `json:"plugin_save_host_revision,omitempty"`
	Phase                         string            `json:"phase"`
	AttemptID                     string            `json:"attempt_id"`
	PostEnableHashWithoutDisabled string            `json:"post_enable_hash_without_disabled,omitempty"`
	PostEnableHostRevision        string            `json:"post_enable_host_revision,omitempty"`
	ResetAt                       time.Time         `json:"reset_at,omitempty"`
	NextCheckAt                   time.Time         `json:"next_check_at,omitempty"`
	BackoffLevel                  int               `json:"backoff_level,omitempty"`
	LastReason                    string            `json:"last_reason,omitempty"`
	LastProbe                     *ProbeSummary     `json:"last_probe,omitempty"`
	Quota                         *QuotaObservation `json:"quota,omitempty"`
	InitialWakeup                 *WakeupRecord     `json:"initial_wakeup,omitempty"`
	ResetWakeup                   *WakeupRecord     `json:"reset_wakeup,omitempty"`
}

// State is the versioned durable document written under state_dir.
type State struct {
	SchemaVersion int                              `json:"schema_version"`
	UpdatedAt     time.Time                        `json:"updated_at"`
	Credentials   map[string]OwnershipRecord       `json:"credentials"`
	Observations  map[string]CredentialObservation `json:"observations,omitempty"`
}

// UsageObservation records only safe evidence that CPA completed a real
// request with a credential. Token counters and failure bodies are excluded.
type UsageObservation struct {
	AuthIndex    string    `json:"auth_index"`
	IdentityHash string    `json:"identity_hash"`
	Status       string    `json:"status"`
	PostReset    bool      `json:"post_reset,omitempty"`
	LastUsedAt   time.Time `json:"last_used_at,omitempty"`
}

// CredentialObservation contains optional per-credential data that can exist
// even when no recovery ownership record exists. Each sub-record is sanitized
// independently so one malformed optional observation cannot hide other rows.
type CredentialObservation struct {
	AuthIndex       string            `json:"auth_index"`
	IdentityHash    string            `json:"identity_hash"`
	LastHealthCheck *ProbeSummary     `json:"last_health_check,omitempty"`
	Quota           *QuotaObservation `json:"quota,omitempty"`
	InitialWakeup   *WakeupRecord     `json:"initial_wakeup,omitempty"`
	ResetWakeup     *WakeupRecord     `json:"reset_wakeup,omitempty"`
	Usage           *UsageObservation `json:"usage,omitempty"`
}

// ProxyProfileProjection is safe proxy catalog data. It contains only a user
// supplied remark and a redacted endpoint; proxy credentials never cross the
// management boundary.
type ProxyProfileProjection struct {
	ID       string `json:"id"`
	Remark   string `json:"remark"`
	Endpoint string `json:"endpoint"`
	Scheme   string `json:"scheme,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     string `json:"port,omitempty"`
}

// ProxyProjection is the only proxy representation crossing the management
// boundary. Userinfo, query, and fragment are never returned.
type ProxyProjection struct {
	Configured bool   `json:"configured"`
	Endpoint   string `json:"endpoint,omitempty"`
	Scheme     string `json:"scheme,omitempty"`
	Host       string `json:"host,omitempty"`
	Port       string `json:"port,omitempty"`
	ProfileID  string `json:"profile_id,omitempty"`
	Remark     string `json:"remark,omitempty"`
}

// QuotaObservation is a safe, user-triggered quota result bound to one
// credential identity. It never contains tokens, raw responses, or prompts.
type QuotaObservation struct {
	AuthIndex    string        `json:"auth_index"`
	IdentityHash string        `json:"identity_hash"`
	Status       string        `json:"status"`
	ResetAt      time.Time     `json:"reset_at,omitempty"`
	CheckedAt    time.Time     `json:"checked_at,omitempty"`
	SafeError    string        `json:"safe_error,omitempty"`
	Windows      []QuotaWindow `json:"windows,omitempty"`
}

// WakeupRecord is safe metadata for one independently gated real wake request.
type WakeupRecord struct {
	Mode          string    `json:"mode"`
	Status        string    `json:"status"`
	IdentityHash  string    `json:"identity_hash,omitempty"`
	WindowKey     string    `json:"window_key,omitempty"`
	AttemptedAt   time.Time `json:"attempted_at,omitempty"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	AttemptCount  int       `json:"attempt_count,omitempty"`
	SafeError     string    `json:"safe_error,omitempty"`
}

// QuotaProjection is the status-page form of a quota observation. The
// identity hash remains persistence-only and never crosses the management
// boundary.
type QuotaProjection struct {
	Status    string        `json:"status"`
	ResetAt   time.Time     `json:"reset_at,omitempty"`
	CheckedAt time.Time     `json:"checked_at,omitempty"`
	SafeError string        `json:"safe_error,omitempty"`
	Windows   []QuotaWindow `json:"windows,omitempty"`
}

func ProjectQuota(in *QuotaObservation) *QuotaProjection {
	if in == nil {
		return nil
	}
	safe := SafeQuotaObservation(in)
	if safe == nil {
		return nil
	}
	return &QuotaProjection{Status: safe.Status, ResetAt: safe.ResetAt, CheckedAt: safe.CheckedAt, SafeError: safe.SafeError, Windows: SafeQuotaWindows(safe.Windows)}
}

// WakeupProjection is the status-page form of a wake record. Credential
// identity hashes and window keys remain persistence-only.
type WakeupProjection struct {
	Mode          string    `json:"mode"`
	Status        string    `json:"status"`
	AttemptedAt   time.Time `json:"attempted_at,omitempty"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at,omitempty"`
	AttemptCount  int       `json:"attempt_count,omitempty"`
	SafeError     string    `json:"safe_error,omitempty"`
}

func ProjectWakeup(in *WakeupRecord, mode string) *WakeupProjection {
	if in == nil {
		return nil
	}
	safe := SafeWakeupRecord(in, mode)
	if safe == nil {
		return nil
	}
	return &WakeupProjection{Mode: safe.Mode, Status: safe.Status, AttemptedAt: safe.AttemptedAt, CompletedAt: safe.CompletedAt, NextAttemptAt: safe.NextAttemptAt, AttemptCount: safe.AttemptCount, SafeError: safe.SafeError}
}

// CredentialProjection is a safe status row.
type CredentialProjection struct {
	AuthIndex     string            `json:"auth_index"`
	AuthID        string            `json:"auth_id,omitempty"`
	FileName      string            `json:"file_name,omitempty"`
	Provider      string            `json:"provider,omitempty"`
	Label         string            `json:"label,omitempty"`
	Disabled      bool              `json:"disabled"`
	ErrorCode     string            `json:"error_code,omitempty"`
	Proxy         ProxyProjection   `json:"proxy"`
	Ownership     *OwnershipSummary `json:"ownership,omitempty"`
	HealthCheck   *ProbeSummary     `json:"health_check,omitempty"`
	Quota         *QuotaProjection  `json:"quota,omitempty"`
	InitialWakeup *WakeupProjection `json:"initial_wakeup,omitempty"`
	ResetWakeup   *WakeupProjection `json:"reset_wakeup,omitempty"`
	UsageStatus   string            `json:"usage_status,omitempty"`
}

// OwnershipSummary intentionally excludes the internal content hash.
type OwnershipSummary struct {
	Phase        string        `json:"phase"`
	DisabledAt   time.Time     `json:"disabled_at"`
	ResetAt      time.Time     `json:"reset_at,omitempty"`
	NextCheckAt  time.Time     `json:"next_check_at,omitempty"`
	BackoffLevel int           `json:"backoff_level"`
	LastReason   string        `json:"last_reason,omitempty"`
	LastProbe    *ProbeSummary `json:"last_probe,omitempty"`
}

// BatchItemResult is used by proxy apply and test operations. It contains no
// raw proxy URL; input URLs are represented by a redacted endpoint or profile
// remark.
type BatchItemResult struct {
	AuthIndex        string `json:"auth_index,omitempty"`
	Action           string `json:"action,omitempty"`
	Endpoint         string `json:"endpoint,omitempty"`
	ProfileID        string `json:"profile_id,omitempty"`
	ProfileRemark    string `json:"profile_remark,omitempty"`
	OldEndpoint      string `json:"old_endpoint,omitempty"`
	OldProfileRemark string `json:"old_profile_remark,omitempty"`
	NewEndpoint      string `json:"new_endpoint,omitempty"`
	NewProfileRemark string `json:"new_profile_remark,omitempty"`
	OK               bool   `json:"ok"`
	Reachable        bool   `json:"reachable,omitempty"`
	HTTPStatus       int    `json:"http_status,omitempty"`
	LatencyMS        int64  `json:"latency_ms,omitempty"`
	ErrorCode        string `json:"error_code,omitempty"`
}

// ProxyTestItem is a safe fixed-target connectivity result.
type ProxyTestItem struct {
	ProfileID     string `json:"profile_id,omitempty"`
	ProfileRemark string `json:"profile_remark,omitempty"`
	Endpoint      string `json:"endpoint,omitempty"`
	Target        string `json:"target"`
	Status        string `json:"status"`
	OK            bool   `json:"ok"`
	Reachable     bool   `json:"reachable"`
	HTTPStatus    int    `json:"http_status,omitempty"`
	LatencyMS     int64  `json:"latency_ms,omitempty"`
	ErrorCode     string `json:"error_code,omitempty"`
	Message       string `json:"message,omitempty"`
}

// ProxyTestSummary is the bounded summary of one fixed-target check.
type ProxyTestSummary struct {
	Total     int   `json:"total"`
	Passed    int   `json:"passed"`
	Warned    int   `json:"warned"`
	Failed    int   `json:"failed"`
	ElapsedMS int64 `json:"elapsed_ms"`
}

// EffectiveConfigProjection is safe to display in the sidebar.
type EffectiveConfigProjection struct {
	Enabled                bool          `json:"enabled"`
	StateDirConfigured     bool          `json:"state_dir_configured"`
	RecoveryEnabled        bool          `json:"recovery_enabled"`
	ScanInterval           time.Duration `json:"scan_interval"`
	InitialBackoff         time.Duration `json:"initial_backoff"`
	MaxBackoff             time.Duration `json:"max_backoff"`
	ProbeEnabled           bool          `json:"probe_enabled"`
	ProbeProvider          string        `json:"probe_provider"`
	ProbeModelConfigured   bool          `json:"probe_model_configured"`
	ProbeTimeout           time.Duration `json:"probe_timeout"`
	QuotaDetectionEnabled  bool          `json:"quota_detection_enabled"`
	DetectHTTP429          bool          `json:"detect_http_429"`
	GenericRateLimit       bool          `json:"classify_generic_rate_limit"`
	ProxyManagementEnabled bool          `json:"proxy_management_enabled"`
	InitialWakeupEnabled   bool          `json:"initial_wakeup_enabled"`
	ResetWakeupEnabled     bool          `json:"reset_wakeup_enabled"`
	WakeupModel            string        `json:"wakeup_model,omitempty"`
	WakeupReasoningEffort  string        `json:"wakeup_reasoning_effort,omitempty"`
}
