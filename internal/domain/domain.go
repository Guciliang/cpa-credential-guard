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
	case "codex_usage_limit_reached", "codex_quota_evidence", "codex_generic_rate_limit", "oversized_failure", "bare_429", "invalid_failure", "non_quota_failure", "recovery_error", "host_error", "unverifiable_pending_enable", "disable_revision_unavailable", "post_enable_revision_unavailable", "post_enable_guard_unavailable", "redisable_failed", "redisable_revision_unavailable", "ownership_guard_failed", "probe_unavailable", "probe_error", "missing_access_token", "health_client_unavailable", "proxy_setup_failed", "request_failed", "timeout", "connection_failed", "canceled", "empty_response", "response_read_failed", "response_too_large", "auth_failed", "unexpected_status", "invalid_inventory", "quota_exhausted", "save_failed", "revision_unavailable", "stale_preview", "post_save_mismatch", "unknown_phase":
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
	out.Windows = SafeQuotaWindows(in.Windows)
	return &out
}

// SafeQuotaWindows is the single boundary sanitizer for upstream-derived quota
// family labels. Only the small internal vocabulary crosses persistence or a
// management projection; arbitrary response keys collapse to "additional".
func SafeQuotaWindows(in []QuotaWindow) []QuotaWindow {
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
	AuthIndex                     string        `json:"auth_index"`
	AuthID                        string        `json:"auth_id,omitempty"`
	FileName                      string        `json:"file_name"`
	DisabledAt                    time.Time     `json:"disabled_at"`
	WasEnabled                    bool          `json:"was_enabled"`
	ContentHashWithoutDisabled    string        `json:"content_hash_without_disabled"`
	PluginSaveHostRevision        string        `json:"plugin_save_host_revision,omitempty"`
	Phase                         string        `json:"phase"`
	AttemptID                     string        `json:"attempt_id"`
	PostEnableHashWithoutDisabled string        `json:"post_enable_hash_without_disabled,omitempty"`
	PostEnableHostRevision        string        `json:"post_enable_host_revision,omitempty"`
	ResetAt                       time.Time     `json:"reset_at,omitempty"`
	NextCheckAt                   time.Time     `json:"next_check_at,omitempty"`
	BackoffLevel                  int           `json:"backoff_level,omitempty"`
	LastReason                    string        `json:"last_reason,omitempty"`
	LastProbe                     *ProbeSummary `json:"last_probe,omitempty"`
}

// State is the versioned durable document written under state_dir.
type State struct {
	SchemaVersion int                        `json:"schema_version"`
	UpdatedAt     time.Time                  `json:"updated_at"`
	Credentials   map[string]OwnershipRecord `json:"credentials"`
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

// CredentialProjection is a safe status row.
type CredentialProjection struct {
	AuthIndex string            `json:"auth_index"`
	AuthID    string            `json:"auth_id,omitempty"`
	FileName  string            `json:"file_name,omitempty"`
	Provider  string            `json:"provider,omitempty"`
	Label     string            `json:"label,omitempty"`
	Disabled  bool              `json:"disabled"`
	Proxy     ProxyProjection   `json:"proxy"`
	Ownership *OwnershipSummary `json:"ownership,omitempty"`
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
}
