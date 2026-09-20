// Package management exposes the authenticated management projection and the
// unauthenticated static sidebar shell. Dynamic data never goes through the
// resource route.
package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cpa-credential-guard/internal/codexhealth"
	"cpa-credential-guard/internal/config"
	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/profiles"
	"cpa-credential-guard/internal/proxy"
	"cpa-credential-guard/internal/state"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	MaxManagementBody = 128 << 10
	MaxBatchItems     = 100
	MaxPlans          = 256
	managementPrefix  = "/plugins/cpa-credential-guard"
	resourcePrefix    = "/v0/resource" + managementPrefix
)

type RecoveryScanner interface{ Scan(context.Context) error }
type WakeupScanner interface{ Scan(context.Context) error }
type recoveryStatus interface{ Enabled() bool }

type Service struct {
	cfg          config.Config
	repo         *credentials.Repository
	store        *state.Store
	recovery     RecoveryScanner
	wakeup       WakeupScanner
	quotaClient  *codexhealth.Client
	checker      *proxy.Checker
	profileStore *profiles.Store
	plansMu      sync.Mutex
	plans        map[string]plan
	now          func() time.Time
	checkerMu    sync.RWMutex
	routeHandler pluginapi.ManagementHandler
}

type plan struct {
	ID        string
	ExpiresAt time.Time
	Items     []planItem
	Fallback  *fallbackPlan
}

type fallbackPlan struct {
	Action      string
	ProfileID   string
	AuthIndexes []string
}
type planItem struct {
	AuthIndex     string
	Name          string
	ProfileID     string
	ProfileRemark string
	RawURL        string
	Clear         bool
	Action        string
	OldProjection domain.ProxyProjection
	Projection    domain.ProxyProjection
	BaselineHash  string
	HostRevision  credentials.RuntimeRevision
	ErrorCode     string
}

type ProxyChange struct {
	AuthIndex string  `json:"auth_index"`
	ProfileID string  `json:"profile_id,omitempty"`
	ProxyURL  *string `json:"proxy_url,omitempty"` // legacy input; UI uses ProfileID
	Clear     bool    `json:"clear,omitempty"`
	Keep      bool    `json:"keep,omitempty"`
}
type ProxyPreviewRequest struct {
	AuthIndex   string                `json:"auth_index,omitempty"`
	Changes     []ProxyChange         `json:"changes,omitempty"`
	AuthIndexes []string              `json:"auth_indexes,omitempty"`
	ProfileID   string                `json:"profile_id,omitempty"`
	ProxyURL    *string               `json:"proxy_url,omitempty"` // legacy input
	Clear       bool                  `json:"clear,omitempty"`
	Fallback    *proxyFallbackRequest `json:"fallback,omitempty"`
}

type proxyFallbackRequest struct {
	Action      string   `json:"action"`
	ProfileID   string   `json:"profile_id"`
	AuthIndexes []string `json:"auth_indexes,omitempty"`
}
type proxyApplyRequest struct {
	PlanID string `json:"plan_id"`
}
type proxyTestRequest struct {
	Proxies    []string `json:"proxies,omitempty"` // retained for direct token-free tests
	ProfileIDs []string `json:"profile_ids,omitempty"`
}
type quotaQueryItem struct {
	AuthIndex string               `json:"auth_index"`
	Status    string               `json:"status"`
	ResetAt   time.Time            `json:"reset_at,omitempty"`
	CheckedAt time.Time            `json:"checked_at,omitempty"`
	Windows   []domain.QuotaWindow `json:"windows,omitempty"`
	ErrorCode string               `json:"error_code,omitempty"`
}
type proxyProfileRequest struct {
	ID                string  `json:"id,omitempty"`
	Remark            string  `json:"remark"`
	ProxyURL          *string `json:"proxy_url,omitempty"`
	FallbackMode      *string `json:"fallback_mode,omitempty"`
	FallbackProfileID *string `json:"fallback_profile_id,omitempty"`
}
type proxyProfileDeleteRequest struct {
	ID        string `json:"id,omitempty"`
	ProfileID string `json:"profile_id,omitempty"`
}

type statusResponse struct {
	Config map[string]any `json:"config"`
	State  struct {
		Available       bool `json:"available"`
		CredentialCount int  `json:"credential_count"`
	} `json:"state"`
	Credentials   []domain.CredentialProjection   `json:"credentials"`
	ProxyGroups   []proxyGroup                    `json:"proxy_groups"`
	ProxyProfiles []domain.ProxyProfileProjection `json:"proxy_profiles"`
}
type proxyGroup struct {
	ProfileID string `json:"profile_id,omitempty"`
	Remark    string `json:"remark,omitempty"`
	Endpoint  string `json:"endpoint"`
	Count     int    `json:"count"`
}

func (s *Service) SetProfileStore(store *profiles.Store) {
	s.profileStore = store
}

func New(cfg config.Config, repo *credentials.Repository, store *state.Store, recovery RecoveryScanner) *Service {
	return NewWithClock(cfg, repo, store, recovery, time.Now)
}
func NewWithClock(cfg config.Config, repo *credentials.Repository, store *state.Store, recovery RecoveryScanner, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	quotaClient := codexhealth.NewClient()
	quotaClient.Timeout = cfg.ProbeTimeout
	quotaClient.Now = now
	return &Service{cfg: cfg, repo: repo, store: store, recovery: recovery, quotaClient: quotaClient, checker: proxy.NewChecker(), plans: make(map[string]plan), now: now}
}
func (s *Service) SetWakeupScanner(scanner WakeupScanner) { s.wakeup = scanner }
func (s *Service) SetQuotaClient(client *codexhealth.Client) {
	if client != nil {
		s.quotaClient = client
	}
}
func (s *Service) SetRouteHandler(handler pluginapi.ManagementHandler) {
	if handler != nil {
		s.routeHandler = handler
	}
}

func (s *Service) SetChecker(checker *proxy.Checker) {
	if checker == nil {
		return
	}
	s.checkerMu.Lock()
	s.checker = checker
	s.checkerMu.Unlock()
}

func (s *Service) checkerForRequest() *proxy.Checker {
	s.checkerMu.Lock()
	defer s.checkerMu.Unlock()
	if s.checker == nil {
		s.checker = proxy.NewChecker()
	}
	return s.checker
}

func (s *Service) RegisterManagement(_ context.Context, req pluginapi.ManagementRegistrationRequest) (pluginapi.ManagementRegistrationResponse, error) {
	_ = req
	handler := s.routeHandler
	if handler == nil {
		handler = s
	}
	return pluginapi.ManagementRegistrationResponse{
		Routes: []pluginapi.ManagementRoute{
			{Method: http.MethodGet, Path: managementPrefix + "/status", Description: "安全的凭证守护状态投影。", Handler: handler},
			{Method: http.MethodGet, Path: managementPrefix + "/proxy/profiles", Description: "查看已保存的代理。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/profiles", Description: "保存代理名称和代理地址。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/profiles/delete", Description: "删除代理。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/preview", Description: "应用前验证代理批次。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/apply", Description: "应用已验证的代理计划。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/test", Description: "测试固定非 Codex 目标的无令牌代理连通性。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/quota/query", Description: "按用户操作查询 Codex 额度。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/recovery/scan", Description: "扫描到期的插件所有权恢复记录和主动唤醒记录。", Handler: handler},
		},
		Resources: []pluginapi.ResourceRoute{{Path: "/index.html", Menu: "CPA 凭证守护", Description: "安全的凭证守护侧边栏。", Handler: &resourceHandler{}}},
	}, nil
}

func managementPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/status"
	}
	if strings.HasPrefix(path, "/v0/management/") {
		path = strings.TrimPrefix(path, "/v0/management")
	}
	if strings.HasPrefix(path, resourcePrefix+"/") {
		path = strings.TrimPrefix(path, resourcePrefix)
	}
	if strings.HasPrefix(path, managementPrefix+"/") {
		path = strings.TrimPrefix(path, managementPrefix)
	}
	if path == "" {
		return "/status"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func (s *Service) HandleManagement(ctx context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	switch managementPath(req.Path) {
	case "/index.html":
		return (&resourceHandler{}).HandleManagement(ctx, req)
	case "/status":
		if req.Method != http.MethodGet {
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
		return s.status(ctx)
	case "/proxy/profiles":
		if !s.cfg.Enabled || !s.cfg.ProxyManagementEnabled {
			return jsonResponse(http.StatusForbidden, map[string]string{"error": "proxy_management_disabled"})
		}
		switch req.Method {
		case http.MethodGet:
			return s.profileList(ctx)
		case http.MethodPost:
			if !validJSONContentType(req.Headers) {
				return jsonResponse(http.StatusUnsupportedMediaType, map[string]string{"error": "content_type_required"})
			}
			return s.profileSave(ctx, req.Body)
		default:
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
	case "/proxy/profiles/delete":
		if !s.cfg.Enabled || !s.cfg.ProxyManagementEnabled {
			return jsonResponse(http.StatusForbidden, map[string]string{"error": "proxy_management_disabled"})
		}
		if req.Method != http.MethodPost {
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
		if !validJSONContentType(req.Headers) {
			return jsonResponse(http.StatusUnsupportedMediaType, map[string]string{"error": "content_type_required"})
		}
		return s.profileDelete(ctx, req.Body)
	case "/proxy/preview":
		if !s.cfg.Enabled || !s.cfg.ProxyManagementEnabled {
			return jsonResponse(http.StatusForbidden, map[string]string{"error": "proxy_management_disabled"})
		}
		if req.Method != http.MethodPost {
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
		if !validJSONContentType(req.Headers) {
			return jsonResponse(http.StatusUnsupportedMediaType, map[string]string{"error": "content_type_required"})
		}
		return s.preview(ctx, req.Body)
	case "/proxy/apply":
		if !s.cfg.Enabled || !s.cfg.ProxyManagementEnabled {
			return jsonResponse(http.StatusForbidden, map[string]string{"error": "proxy_management_disabled"})
		}
		if req.Method != http.MethodPost {
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
		if !validJSONContentType(req.Headers) {
			return jsonResponse(http.StatusUnsupportedMediaType, map[string]string{"error": "content_type_required"})
		}
		return s.apply(ctx, req.Body)
	case "/proxy/test":
		if !s.cfg.Enabled || !s.cfg.ProxyManagementEnabled {
			return jsonResponse(http.StatusForbidden, map[string]string{"error": "proxy_management_disabled"})
		}
		if req.Method != http.MethodPost {
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
		if !validJSONContentType(req.Headers) {
			return jsonResponse(http.StatusUnsupportedMediaType, map[string]string{"error": "content_type_required"})
		}
		return s.test(ctx, req.Body)
	case "/quota/query":
		if req.Method != http.MethodPost {
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
		if !s.cfg.Enabled {
			return jsonResponse(http.StatusForbidden, map[string]string{"error": "credential_guard_disabled"})
		}
		if !validJSONContentType(req.Headers) {
			return jsonResponse(http.StatusUnsupportedMediaType, map[string]string{"error": "content_type_required"})
		}
		return s.queryQuota(ctx, req.Body)
	case "/recovery/scan":
		if req.Method != http.MethodPost {
			return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		}
		return s.scan(ctx)
	default:
		return jsonResponse(http.StatusNotFound, map[string]string{"error": "not_found"})
	}
}

func (s *Service) status(ctx context.Context) (pluginapi.ManagementResponse, error) {
	out := statusResponse{Config: s.cfg.EffectiveProjection(), Credentials: []domain.CredentialProjection{}, ProxyGroups: []proxyGroup{}, ProxyProfiles: []domain.ProxyProfileProjection{}}
	if s.profileStore != nil {
		out.ProxyProfiles = s.profileStore.List()
	}
	if s.store != nil {
		out.State.Available = true
		out.State.CredentialCount = len(s.store.Snapshot().Credentials)
	}
	if !s.cfg.Enabled || s.repo == nil {
		return jsonResponse(http.StatusOK, out)
	}
	entries, err := s.repo.List(ctx)
	if err != nil {
		return jsonResponse(http.StatusOK, map[string]any{"config": out.Config, "state": map[string]any{"available": false}, "credentials": []any{}, "proxy_groups": []any{}, "proxy_profiles": out.ProxyProfiles, "error": "host_unavailable"})
	}
	groups := map[string]*proxyGroup{}
	for _, entry := range entries {
		if !isCodex(entry.Provider, entry.Type) {
			continue
		}
		snap, err := s.repo.Snapshot(ctx, entry.AuthIndex)
		if err != nil {
			row := domain.CredentialProjection{AuthIndex: entry.AuthIndex, AuthID: entry.ID, FileName: entry.Name, Provider: entry.Provider, Label: entry.Label, ErrorCode: "host_error", Quota: domain.ProjectQuota(&domain.QuotaObservation{AuthIndex: entry.AuthIndex, Status: domain.QuotaUnknown, SafeError: "host_error"})}
			out.Credentials = append(out.Credentials, row)
			continue
		}
		proxyProjection := proxy.Redact(snap.ProxyURL)
		if profile, ok := s.matchProfile(snap.ProxyURL); ok {
			proxyProjection.ProfileID = profile.ID
			proxyProjection.Remark = profile.Remark
		}
		row := domain.CredentialProjection{AuthIndex: entry.AuthIndex, AuthID: entry.ID, FileName: snap.Name, Provider: entry.Provider, Label: entry.Label, Disabled: snap.Disabled, Proxy: proxyProjection, Quota: domain.ProjectQuota(&domain.QuotaObservation{AuthIndex: entry.AuthIndex, Status: domain.QuotaUnknown})}
		if s.store != nil {
			if record, ok := s.store.Get("codex:" + entry.AuthIndex); ok && record.ContentHashWithoutDisabled == snap.ContentHashWithoutDisabled {
				safeProbe := domain.SafeProbeSummary(record.LastProbe)
				row.Ownership = &domain.OwnershipSummary{Phase: record.Phase, DisabledAt: record.DisabledAt, ResetAt: record.ResetAt, NextCheckAt: record.NextCheckAt, BackoffLevel: record.BackoffLevel, LastReason: domain.SafeCode(record.LastReason), LastProbe: safeProbe}
				row.HealthCheck = safeProbe
				if record.Quota != nil && record.Quota.IdentityHash == snap.ContentHashWithoutDisabled {
					row.Quota = domain.ProjectQuota(record.Quota)
				} else if safeProbe != nil {
					// Older state files persisted only the health summary. Rebuild
					// the safe quota projection without making a network request.
					fallback := codexhealth.QuotaObservationFromProbe(entry.AuthIndex, snap.ContentHashWithoutDisabled, *safeProbe)
					row.Quota = domain.ProjectQuota(&fallback)
				}
				if !record.ResetAt.IsZero() && row.Quota.Status == domain.QuotaUnknown {
					// The ownership record itself is the identity-bound evidence
					// created when quota exhaustion caused the guarded disable.
					fallback := domain.QuotaObservation{AuthIndex: entry.AuthIndex, IdentityHash: snap.ContentHashWithoutDisabled, Status: domain.QuotaExhausted, ResetAt: record.ResetAt, CheckedAt: record.DisabledAt, SafeError: "quota_exhausted"}
					row.Quota = domain.ProjectQuota(&fallback)
				}
				if record.InitialWakeup != nil && record.InitialWakeup.IdentityHash == snap.ContentHashWithoutDisabled {
					row.InitialWakeup = domain.ProjectWakeup(record.InitialWakeup, domain.WakeupInitial)
				}
				if record.ResetWakeup != nil && record.ResetWakeup.IdentityHash == snap.ContentHashWithoutDisabled {
					row.ResetWakeup = domain.ProjectWakeup(record.ResetWakeup, domain.WakeupReset)
				}
			}
			if observation, ok := s.store.GetObservation("codex:" + entry.AuthIndex); ok {
				if observation.IdentityHash == snap.ContentHashWithoutDisabled {
					if observation.LastHealthCheck != nil {
						row.HealthCheck = domain.SafeProbeSummary(observation.LastHealthCheck)
					}
					if observation.Quota != nil && observation.Quota.IdentityHash == snap.ContentHashWithoutDisabled {
						row.Quota = domain.ProjectQuota(observation.Quota)
					}
					if observation.InitialWakeup != nil && observation.InitialWakeup.IdentityHash == snap.ContentHashWithoutDisabled {
						row.InitialWakeup = domain.ProjectWakeup(observation.InitialWakeup, domain.WakeupInitial)
					}
					if observation.ResetWakeup != nil && observation.ResetWakeup.IdentityHash == snap.ContentHashWithoutDisabled {
						row.ResetWakeup = domain.ProjectWakeup(observation.ResetWakeup, domain.WakeupReset)
					}
					if observation.Usage != nil && observation.Usage.IdentityHash == snap.ContentHashWithoutDisabled {
						switch observation.Usage.Status {
						case domain.UsageNormal:
							row.UsageStatus = domain.UsageNormal
							if observation.Usage.PostReset {
								row.UsageStatus = "post_reset_cpa_usage"
							}
						case domain.UsageRequestFailed, domain.UsageUnknown, "unknown":
							row.UsageStatus = observation.Usage.Status
						}
					}
				}
			}
		}
		if row.Quota == nil {
			row.Quota = domain.ProjectQuota(&domain.QuotaObservation{AuthIndex: entry.AuthIndex, Status: domain.QuotaUnknown})
		}
		if !row.Quota.ResetAt.IsZero() && !row.Quota.ResetAt.After(s.now()) {
			row.Quota.ResetAt = time.Time{}
		}
		out.Credentials = append(out.Credentials, row)
		wipeCredentialJSON(snap.JSON)
		if row.Proxy.Configured {
			key := row.Proxy.ProfileID
			if key == "" {
				key = "endpoint:" + row.Proxy.Endpoint
			}
			if groups[key] == nil {
				remark := row.Proxy.Remark
				if remark == "" {
					remark = "未关联名称"
				}
				groups[key] = &proxyGroup{ProfileID: row.Proxy.ProfileID, Remark: remark, Endpoint: row.Proxy.Endpoint}
			}
			groups[key].Count++
		}
	}
	for _, group := range groups {
		out.ProxyGroups = append(out.ProxyGroups, *group)
	}
	sort.Slice(out.ProxyGroups, func(i, j int) bool {
		if out.ProxyGroups[i].Remark == out.ProxyGroups[j].Remark {
			return out.ProxyGroups[i].Endpoint < out.ProxyGroups[j].Endpoint
		}
		return out.ProxyGroups[i].Remark < out.ProxyGroups[j].Remark
	})
	return jsonResponse(http.StatusOK, out)
}

func (s *Service) matchProfile(rawURL string) (profiles.Profile, bool) {
	if s.profileStore == nil || strings.TrimSpace(rawURL) == "" {
		return profiles.Profile{}, false
	}
	return s.profileStore.Match(rawURL)
}

func (s *Service) profileList(_ context.Context) (pluginapi.ManagementResponse, error) {
	if s.profileStore == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "profile_store_unavailable"})
	}
	return jsonResponse(http.StatusOK, map[string]any{"profiles": s.profileStore.List()})
}

func (s *Service) profileSave(_ context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	if s.profileStore == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "profile_store_unavailable"})
	}
	var request proxyProfileRequest
	if err := decodeBody(raw, &request); err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
	}
	profile, err := s.profileStore.SaveWithFallback(request.ID, request.Remark, request.ProxyURL, request.FallbackMode, request.FallbackProfileID)
	if err != nil {
		if errors.Is(err, profiles.ErrNotFound) {
			return jsonResponse(http.StatusNotFound, map[string]string{"error": "profile_not_found"})
		}
		if errors.Is(err, profiles.ErrActiveFallback) {
			return jsonResponse(http.StatusConflict, map[string]string{"error": "fallback_active"})
		}
		if errors.Is(err, profiles.ErrInvalid) || strings.Contains(err.Error(), "proxy profile remark already exists") {
			return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "invalid_proxy_profile"})
		}
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "profile_store_unavailable"})
	}
	return jsonResponse(http.StatusOK, map[string]any{"profile": profile.Projection})
}

func (s *Service) profileDelete(_ context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	if s.profileStore == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "profile_store_unavailable"})
	}
	var request proxyProfileDeleteRequest
	if err := decodeBody(raw, &request); err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "profile_id_required"})
	}
	requestID := strings.TrimSpace(request.ProfileID)
	if requestID == "" {
		requestID = strings.TrimSpace(request.ID)
	}
	if requestID == "" {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "profile_id_required"})
	}
	if err := s.profileStore.Delete(requestID); err != nil {
		if errors.Is(err, profiles.ErrNotFound) {
			return jsonResponse(http.StatusNotFound, map[string]string{"error": "profile_not_found"})
		}
		if errors.Is(err, profiles.ErrReferenced) {
			return jsonResponse(http.StatusConflict, map[string]string{"error": "profile_in_use"})
		}
		if errors.Is(err, profiles.ErrActiveFallback) {
			return jsonResponse(http.StatusConflict, map[string]string{"error": "fallback_active"})
		}
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "profile_store_unavailable"})
	}
	return jsonResponse(http.StatusOK, map[string]any{"deleted": true, "id": requestID})
}

func (s *Service) prunePlansLocked(now time.Time) {
	for id, p := range s.plans {
		if !now.Before(p.ExpiresAt) {
			delete(s.plans, id)
		}
	}
	for len(s.plans) >= MaxPlans {
		var oldestID string
		var oldest time.Time
		for id, p := range s.plans {
			if oldestID == "" || p.ExpiresAt.Before(oldest) {
				oldestID, oldest = id, p.ExpiresAt
			}
		}
		if oldestID == "" {
			return
		}
		delete(s.plans, oldestID)
	}
}

func (s *Service) resolveProxyChange(change ProxyChange) (string, profiles.Profile, string) {
	if change.Keep {
		return "", profiles.Profile{}, "keep"
	}
	profileID := strings.TrimSpace(change.ProfileID)
	if profileID != "" {
		if change.ProxyURL != nil {
			return "", profiles.Profile{}, "ambiguous_proxy_change"
		}
		if s.profileStore == nil {
			return "", profiles.Profile{}, "profile_store_unavailable"
		}
		profile, ok := s.profileStore.Get(profileID)
		if !ok {
			return "", profiles.Profile{}, "profile_not_found"
		}
		return profile.ProxyURL, profile, ""
	}
	if change.ProxyURL == nil {
		return "", profiles.Profile{}, "proxy_profile_required"
	}
	validated, err := proxy.Validate(*change.ProxyURL)
	if err != nil {
		return "", profiles.Profile{}, "invalid_proxy"
	}
	if profile, ok := s.matchProfile(validated.URL.String()); ok {
		return validated.URL.String(), profile, ""
	}
	return validated.URL.String(), profiles.Profile{}, ""
}

func normalizeFallbackIndexes(indexes []string) []string {
	seen := make(map[string]struct{}, len(indexes))
	out := make([]string, 0, len(indexes))
	for _, index := range indexes {
		index = strings.TrimSpace(index)
		if index == "" || len(index) > 256 || strings.ContainsAny(index, "\x00\r\n") {
			continue
		}
		if _, ok := seen[index]; ok {
			continue
		}
		seen[index] = struct{}{}
		out = append(out, index)
	}
	sort.Strings(out)
	return out
}

func (s *Service) validateFallbackRequest(request *proxyFallbackRequest) (*fallbackPlan, string) {
	if request == nil {
		return nil, ""
	}
	if s.profileStore == nil {
		return nil, "profile_store_unavailable"
	}
	profileID := strings.TrimSpace(request.ProfileID)
	profile, ok := s.profileStore.Get(profileID)
	if !ok {
		return nil, "profile_not_found"
	}
	indexes := normalizeFallbackIndexes(request.AuthIndexes)
	action := strings.TrimSpace(request.Action)
	if action == "restore" && len(indexes) == 0 {
		indexes = normalizeFallbackIndexes(profile.FallbackAuthIndexes)
	}
	if len(indexes) == 0 || len(indexes) > MaxBatchItems {
		return nil, "invalid_fallback_request"
	}
	switch action {
	case "activate":
		if profile.Projection.FallbackMode == domain.FallbackNone || profile.Projection.FallbackMode == "" {
			return nil, "fallback_not_configured"
		}
	case "restore":
		if profile.Projection.FallbackState != "active" {
			return nil, "fallback_not_active"
		}
		allowed := make(map[string]struct{}, len(profile.FallbackAuthIndexes))
		for _, index := range profile.FallbackAuthIndexes {
			allowed[index] = struct{}{}
		}
		for _, index := range indexes {
			if _, ok := allowed[index]; !ok {
				return nil, "invalid_fallback_request"
			}
		}
	default:
		return nil, "invalid_fallback_request"
	}
	return &fallbackPlan{Action: action, ProfileID: profile.ID, AuthIndexes: indexes}, ""
}

func (s *Service) preview(ctx context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	var request ProxyPreviewRequest
	if err := decodeBody(raw, &request); err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
	}
	fallback, fallbackCode := s.validateFallbackRequest(request.Fallback)
	if fallbackCode != "" {
		return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": fallbackCode})
	}
	changes := request.Changes
	if len(changes) == 0 && request.AuthIndex != "" {
		changes = append(changes, ProxyChange{AuthIndex: request.AuthIndex, ProfileID: request.ProfileID, ProxyURL: request.ProxyURL, Clear: request.Clear})
	}
	if len(changes) == 0 && len(request.AuthIndexes) > 0 {
		for _, index := range request.AuthIndexes {
			changes = append(changes, ProxyChange{AuthIndex: index, ProfileID: request.ProfileID, ProxyURL: request.ProxyURL, Clear: request.Clear})
		}
	}
	if len(changes) == 0 && fallback != nil && fallback.Action == "restore" {
		for _, index := range fallback.AuthIndexes {
			changes = append(changes, ProxyChange{AuthIndex: index, ProfileID: fallback.ProfileID})
		}
	}
	if len(changes) == 0 || len(changes) > MaxBatchItems {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_batch_size"})
	}
	if s.repo == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "host_unavailable"})
	}
	entries, err := s.repo.List(ctx)
	if err != nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "host_unavailable"})
	}
	byIndex := map[string]pluginapi.HostAuthFileEntry{}
	ambiguousIndexes := map[string]bool{}
	for _, entry := range entries {
		if _, exists := byIndex[entry.AuthIndex]; exists {
			ambiguousIndexes[entry.AuthIndex] = true
			continue
		}
		byIndex[entry.AuthIndex] = entry
	}
	items := make([]planItem, 0, len(changes))
	results := make([]domain.BatchItemResult, 0, len(changes))
	seen := map[string]bool{}
	for _, change := range changes {
		item := planItem{AuthIndex: strings.TrimSpace(change.AuthIndex)}
		result := domain.BatchItemResult{AuthIndex: item.AuthIndex}
		if item.AuthIndex == "" {
			item.ErrorCode = "auth_index_required"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		if seen[item.AuthIndex] {
			item.ErrorCode = "duplicate_auth_index"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		seen[item.AuthIndex] = true
		if ambiguousIndexes[item.AuthIndex] {
			item.ErrorCode = "duplicate_auth_index"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		entry, ok := byIndex[item.AuthIndex]
		if !ok || !isCodex(entry.Provider, entry.Type) {
			item.ErrorCode = "codex_credential_not_found"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		snap, err := s.repo.Snapshot(ctx, item.AuthIndex)
		if err != nil {
			item.ErrorCode = "credential_unavailable"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		defer wipeCredentialJSON(snap.JSON)
		item.Name = snap.Name
		item.BaselineHash = snap.FullHash
		item.HostRevision = snap.Revision
		item.Clear = change.Clear
		if !snap.RuntimeOK || snap.Revision == "" {
			item.ErrorCode = "revision_unavailable"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		oldProjection := proxy.Redact(snap.ProxyURL)
		if oldProfile, ok := s.matchProfile(snap.ProxyURL); ok {
			oldProjection.ProfileID = oldProfile.ID
			oldProjection.Remark = oldProfile.Remark
		}
		item.OldProjection = oldProjection
		result.OldEndpoint = oldProjection.Endpoint
		result.OldProfileRemark = oldProjection.Remark
		profileID := strings.TrimSpace(change.ProfileID)
		if (change.Keep && (change.Clear || change.ProxyURL != nil || profileID != "")) || (change.Clear && (change.ProxyURL != nil || profileID != "" || change.Keep)) {
			item.ErrorCode = "ambiguous_proxy_change"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		if change.Keep {
			item.Action = "keep"
			item.Projection = oldProjection
			item.ProfileID = oldProjection.ProfileID
			item.ProfileRemark = oldProjection.Remark
			result.Action = item.Action
			result.Endpoint = oldProjection.Endpoint
			result.ProfileID = oldProjection.ProfileID
			result.ProfileRemark = oldProjection.Remark
			result.NewEndpoint = oldProjection.Endpoint
			result.NewProfileRemark = oldProjection.Remark
			result.OK = true
			items = append(items, item)
			results = append(results, result)
			continue
		}
		if change.Clear {
			item.Action = "clear"
			result.Action = "clear"
		} else {
			rawURL, profile, resolveCode := s.resolveProxyChange(change)
			if resolveCode != "" {
				item.ErrorCode = resolveCode
				result.ErrorCode = item.ErrorCode
				results = append(results, result)
				items = append(items, item)
				continue
			}
			validated, validateErr := proxy.Validate(rawURL)
			if validateErr != nil {
				item.ErrorCode = "invalid_proxy"
				result.ErrorCode = item.ErrorCode
				results = append(results, result)
				items = append(items, item)
				continue
			}
			item.RawURL = validated.URL.String()
			item.Projection = validated.Projection
			if profile.ID != "" {
				item.ProfileID = profile.ID
				item.ProfileRemark = profile.Remark
				item.Projection.ProfileID = profile.ID
				item.Projection.Remark = profile.Remark
			}
			if snap.ProxyURL == "" {
				item.Action = "set"
			} else {
				item.Action = "replace"
			}
			result.Action = item.Action
			result.Endpoint = item.Projection.Endpoint
			result.ProfileID = item.ProfileID
			result.ProfileRemark = item.ProfileRemark
			result.NewEndpoint = item.Projection.Endpoint
			result.NewProfileRemark = item.ProfileRemark
		}
		if item.Action == "clear" {
			result.Endpoint = ""
			result.ProfileID = ""
			result.ProfileRemark = ""
			result.NewEndpoint = ""
			result.NewProfileRemark = ""
		}
		result.OK = true
		items = append(items, item)
		results = append(results, result)
	}
	valid := false
	validFallbackIndexes := make(map[string]struct{})
	for _, item := range items {
		if item.ErrorCode == "" {
			valid = true
			if fallback != nil {
				validFallbackIndexes[item.AuthIndex] = struct{}{}
			}
		}
	}
	if fallback != nil {
		profile, ok := s.profileStore.Get(fallback.ProfileID)
		if !ok {
			return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "profile_not_found"})
		}
		requested := make(map[string]struct{}, len(fallback.AuthIndexes))
		for _, authIndex := range fallback.AuthIndexes {
			requested[authIndex] = struct{}{}
			if _, ok := validFallbackIndexes[authIndex]; !ok {
				return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "invalid_fallback_request"})
			}
		}
		for _, item := range items {
			if item.ErrorCode != "" {
				continue
			}
			if _, ok := requested[item.AuthIndex]; !ok {
				return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "invalid_fallback_request"})
			}
			if fallback.Action == "activate" {
				// A fallback may only be activated for a credential that still
				// uses the profile whose connectivity failed. Otherwise a forged
				// management request could mark an unrelated credential as
				// recoverable and later restore it to the wrong proxy.
				if item.OldProjection.ProfileID != profile.ID {
					return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "invalid_fallback_request"})
				}
				switch profile.FallbackMode {
				case domain.FallbackDirect:
					if !item.Clear {
						return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "invalid_fallback_request"})
					}
				case domain.FallbackProfile:
					if item.Clear || item.ProfileID != profile.FallbackProfileID {
						return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "invalid_fallback_request"})
					}
				}
			} else {
				expectedFallbackID := ""
				if profile.FallbackMode == domain.FallbackProfile {
					expectedFallbackID = profile.FallbackProfileID
				}
				// Restore must target a credential that is currently using the
				// configured fallback (or direct access), not merely any listed
				// auth index from an older active record.
				if item.OldProjection.ProfileID != expectedFallbackID || item.Clear || item.ProfileID != profile.ID {
					return jsonResponse(http.StatusUnprocessableEntity, map[string]string{"error": "invalid_fallback_request"})
				}
			}
		}
	}
	planID := ""
	expiresAt := time.Time{}
	if valid {
		planID = newPlanID()
		expiresAt = s.now().Add(5 * time.Minute)
		if fallback != nil {
			fallback.AuthIndexes = append([]string(nil), fallback.AuthIndexes...)
		}
		p := plan{ID: planID, ExpiresAt: expiresAt, Items: items, Fallback: fallback}
		s.plansMu.Lock()
		s.prunePlansLocked(s.now())
		s.plans[planID] = p
		s.plansMu.Unlock()
	}
	status := http.StatusOK
	if !valid {
		status = http.StatusUnprocessableEntity
	}
	return jsonResponse(status, map[string]any{"plan_id": planID, "expires_at": expiresAt, "items": results})
}

func (s *Service) apply(ctx context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	var request proxyApplyRequest
	if err := decodeBody(raw, &request); err != nil || request.PlanID == "" {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "plan_id_required"})
	}
	s.plansMu.Lock()
	s.prunePlansLocked(s.now())
	p, ok := s.plans[request.PlanID]
	if ok {
		delete(s.plans, request.PlanID)
	}
	s.plansMu.Unlock()
	if !ok {
		return jsonResponse(http.StatusConflict, map[string]string{"error": "plan_expired_or_unknown"})
	}
	if !s.now().Before(p.ExpiresAt) {
		return jsonResponse(http.StatusConflict, map[string]string{"error": "plan_expired"})
	}
	results := make([]domain.BatchItemResult, 0, len(p.Items))
	fallbackSuccess := make([]string, 0)
	for _, item := range p.Items {
		result := domain.BatchItemResult{AuthIndex: item.AuthIndex, Action: item.Action, Endpoint: item.Projection.Endpoint, ProfileID: item.ProfileID, ProfileRemark: item.ProfileRemark, OldEndpoint: item.OldProjection.Endpoint, OldProfileRemark: item.OldProjection.Remark, NewEndpoint: item.Projection.Endpoint, NewProfileRemark: item.ProfileRemark}
		if item.ErrorCode != "" {
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			continue
		}
		if item.Action == "keep" {
			result.OK = true
			results = append(results, result)
			continue
		}
		mutation, err := s.repo.SetProxy(ctx, item.AuthIndex, item.RawURL, item.Clear, credentials.Guard{FullHash: item.BaselineHash, HostRevision: item.HostRevision, RequireRuntime: true})
		defer wipeCredentialJSON(mutation.Before.JSON)
		defer wipeCredentialJSON(mutation.After.JSON)
		if err != nil {
			result.ErrorCode = safeMutationError(err)
			results = append(results, result)
			continue
		}
		if item.Clear {
			if mutation.After.ProxyURL != "" {
				result.ErrorCode = "post_save_mismatch"
				results = append(results, result)
				continue
			}
		} else if mutation.After.ProxyURL != item.RawURL {
			result.ErrorCode = "post_save_mismatch"
			results = append(results, result)
			continue
		}
		result.OK = true
		result.Endpoint = proxy.Redact(mutation.After.ProxyURL).Endpoint
		if profile, ok := s.matchProfile(mutation.After.ProxyURL); ok {
			result.ProfileID = profile.ID
			result.ProfileRemark = profile.Remark
		}
		result.NewEndpoint = result.Endpoint
		result.NewProfileRemark = result.ProfileRemark
		if p.Fallback != nil && result.OK {
			fallbackSuccess = append(fallbackSuccess, item.AuthIndex)
		}
		results = append(results, result)
	}
	response := map[string]any{"plan_id": request.PlanID, "items": results}
	if p.Fallback != nil && len(fallbackSuccess) > 0 && s.profileStore != nil {
		var fallbackErr error
		if p.Fallback.Action == "activate" {
			fallbackErr = s.profileStore.MarkFallback(p.Fallback.ProfileID, fallbackSuccess)
		} else {
			fallbackErr = s.profileStore.ClearFallback(p.Fallback.ProfileID, fallbackSuccess)
		}
		if fallbackErr != nil {
			response["fallback_error"] = "save_failed"
		}
	}
	return jsonResponse(http.StatusOK, response)
}

func (s *Service) test(ctx context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	var request proxyTestRequest
	if err := decodeBody(raw, &request); err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
	}
	if len(request.Proxies)+len(request.ProfileIDs) == 0 || len(request.Proxies)+len(request.ProfileIDs) > MaxBatchItems {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_proxy_batch"})
	}
	if len(request.ProfileIDs) > 0 && s.profileStore == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "profile_store_unavailable"})
	}
	checker := s.checkerForRequest()
	started := time.Now()
	items := make([]domain.ProxyTestItem, 0, (len(request.Proxies)+len(request.ProfileIDs))*len(proxy.FixedTargetIDs()))
	addQuality := func(profileID, profileRemark string, quality proxy.QualityResult) {
		for _, target := range quality.Items {
			items = append(items, domain.ProxyTestItem{ProfileID: profileID, ProfileRemark: profileRemark, Endpoint: quality.Projection.Endpoint, Target: target.Target, Status: target.Status, OK: target.Status == "pass", Reachable: target.Reachable, HTTPStatus: target.HTTPStatus, LatencyMS: target.Latency.Milliseconds(), ErrorCode: target.ErrorCode, Message: target.Message})
		}
	}
	for _, profileID := range request.ProfileIDs {
		profile, ok := s.profileStore.Get(strings.TrimSpace(profileID))
		if !ok {
			items = append(items, domain.ProxyTestItem{ProfileID: strings.TrimSpace(profileID), Status: "fail", ErrorCode: "profile_not_found", Message: "代理不存在"})
			continue
		}
		addQuality(profile.ID, profile.Remark, checker.CheckQuality(ctx, profile.ProxyURL))
	}
	for _, rawProxy := range request.Proxies {
		profileID, profileRemark := "", ""
		if profile, ok := s.matchProfile(rawProxy); ok {
			profileID, profileRemark = profile.ID, profile.Remark
		}
		addQuality(profileID, profileRemark, checker.CheckQuality(ctx, rawProxy))
	}
	summary := domain.ProxyTestSummary{Total: len(items)}
	for _, item := range items {
		switch item.Status {
		case "pass":
			summary.Passed++
		case "warn", "challenge":
			summary.Warned++
		default:
			summary.Failed++
		}
	}
	summary.ElapsedMS = time.Since(started).Milliseconds()
	return jsonResponse(http.StatusOK, map[string]any{"items": items, "summary": summary})
}
func (s *Service) queryQuota(ctx context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	if !s.cfg.ProbeEnabled {
		return jsonResponse(http.StatusOK, map[string]any{"items": []quotaQueryItem{}, "error": "quota_probe_disabled"})
	}
	if s.repo == nil || s.store == nil || s.quotaClient == nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "host_unavailable"})
	}
	var payload map[string]json.RawMessage
	if err := decodeBody(raw, &payload); err != nil || payload == nil || len(payload) > 1 {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
	}
	requestAuthIndex := ""
	if len(payload) > 0 {
		value, present := payload["auth_index"]
		if !present {
			return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		}
		if err := json.Unmarshal(value, &requestAuthIndex); err != nil || strings.TrimSpace(requestAuthIndex) == "" {
			return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		}
		requestAuthIndex = strings.TrimSpace(requestAuthIndex)
		if len(requestAuthIndex) > 256 {
			return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		}
	}
	entries, err := s.repo.List(ctx)
	if err != nil {
		return jsonResponse(http.StatusServiceUnavailable, map[string]string{"error": "host_unavailable"})
	}
	type target struct {
		index     string
		errorCode string
	}
	counts := make(map[string]int, len(entries))
	codexEntries := make(map[string]bool, len(entries))
	for _, entry := range entries {
		index := strings.TrimSpace(entry.AuthIndex)
		if index == "" {
			continue
		}
		counts[index]++
		if isCodex(entry.Provider, entry.Type) {
			codexEntries[index] = true
		}
	}
	targets := make([]target, 0, len(entries))
	if requestAuthIndex != "" {
		if counts[requestAuthIndex] > 1 {
			return jsonResponse(http.StatusOK, map[string]any{"items": []quotaQueryItem{{AuthIndex: requestAuthIndex, Status: domain.QuotaUnknown, ErrorCode: "duplicate_auth_index"}}})
		}
		if counts[requestAuthIndex] == 0 || !codexEntries[requestAuthIndex] {
			return jsonResponse(http.StatusOK, map[string]any{"items": []quotaQueryItem{{AuthIndex: requestAuthIndex, Status: domain.QuotaUnknown, ErrorCode: "codex_credential_not_found"}}})
		}
		targets = append(targets, target{index: requestAuthIndex})
	} else {
		seen := make(map[string]struct{}, len(entries))
		for _, entry := range entries {
			index := strings.TrimSpace(entry.AuthIndex)
			if !isCodex(entry.Provider, entry.Type) || index == "" {
				continue
			}
			if _, exists := seen[index]; exists {
				continue
			}
			seen[index] = struct{}{}
			target := target{index: index}
			if counts[index] > 1 {
				target.errorCode = "duplicate_auth_index"
			}
			targets = append(targets, target)
		}
		sort.Slice(targets, func(i, j int) bool { return targets[i].index < targets[j].index })
	}
	items := make([]quotaQueryItem, len(targets))
	// The per-auth repository lock is the important safety boundary. Queries
	// are deliberately bounded to four workers; each worker reads a fresh Host
	// snapshot and stores only a sanitized observation. A worker pool keeps the
	// global "all credentials" action bounded even when the Host contains many
	// entries, while preserving deterministic response ordering.
	if len(targets) == 0 {
		return jsonResponse(http.StatusOK, map[string]any{"items": []quotaQueryItem{}})
	}
	jobs := make(chan int)
	workerCount := 4
	if len(targets) < workerCount {
		workerCount = len(targets)
	}
	var wg sync.WaitGroup
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				item := targets[index]
				if item.errorCode != "" {
					items[index] = quotaQueryItem{AuthIndex: item.index, Status: domain.QuotaUnknown, ErrorCode: item.errorCode}
					continue
				}
				items[index] = s.queryQuotaOne(ctx, item.index)
			}
		}()
	}
	for index := range targets {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	return jsonResponse(http.StatusOK, map[string]any{"items": items})
}

func (s *Service) queryQuotaOne(ctx context.Context, authIndex string) quotaQueryItem {
	item := quotaQueryItem{AuthIndex: authIndex, Status: domain.QuotaUnknown}
	var observation domain.QuotaObservation
	var saveErr error
	err := s.repo.WithLock(ctx, authIndex, func() error {
		snap, err := s.repo.Snapshot(ctx, authIndex)
		if err != nil {
			item.ErrorCode = "host_error"
			return nil
		}
		defer wipeCredentialJSON(snap.JSON)
		identityHash := snap.ContentHashWithoutDisabled
		summary, probeErr := s.quotaClient.Probe(ctx, snap.JSON)
		if probeErr != nil {
			checkedAt := s.now().UTC()
			observation = domain.QuotaObservation{AuthIndex: authIndex, IdentityHash: identityHash, Status: domain.QuotaUnknown, CheckedAt: checkedAt, SafeError: "quota_query_failed"}
		} else {
			observation = codexhealth.QuotaObservationFromProbe(authIndex, identityHash, summary)
		}
		item.Status = observation.Status
		item.ResetAt = observation.ResetAt
		item.CheckedAt = observation.CheckedAt
		item.Windows = observation.Windows
		item.ErrorCode = observation.SafeError
		if observation.AuthIndex == "" {
			if item.ErrorCode == "" {
				item.ErrorCode = "quota_query_failed"
			}
			return nil
		}
		saveErr = s.store.Update(func(next *domain.State) error {
			if next.Observations == nil {
				next.Observations = map[string]domain.CredentialObservation{}
			}
			key := "codex:" + authIndex
			current := next.Observations[key]
			if current.IdentityHash != "" && current.IdentityHash != observation.IdentityHash {
				current = domain.CredentialObservation{}
			}
			current.AuthIndex = authIndex
			current.IdentityHash = observation.IdentityHash
			current.Quota = &observation
			next.Observations[key] = current
			if record, ok := next.Credentials[key]; ok {
				record.Quota = &observation
				next.Credentials[key] = record
			}
			return nil
		})
		return nil
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			item.ErrorCode = "canceled"
		} else if errors.Is(err, context.DeadlineExceeded) {
			item.ErrorCode = "timeout"
		} else {
			item.ErrorCode = "quota_query_failed"
		}
		return item
	}
	if item.ErrorCode == "host_error" || observation.AuthIndex == "" {
		if item.ErrorCode == "" {
			item.ErrorCode = "quota_query_failed"
		}
		return item
	}
	if saveErr != nil {
		item.Status = domain.QuotaUnknown
		item.ErrorCode = "save_failed"
	}
	return item
}

func wipeCredentialJSON(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (s *Service) scan(ctx context.Context) (pluginapi.ManagementResponse, error) {
	if !s.cfg.Enabled {
		return jsonResponse(http.StatusForbidden, map[string]any{"started": false, "error": "credential_guard_disabled"})
	}
	started := false
	incomplete := false
	// Keep the consuming reset wake ahead of the read-only recovery probe so
	// the due scan observes the persisted reset window before recovery can
	// retire or replace its ownership record.
	if s.wakeup != nil {
		if status, ok := s.wakeup.(recoveryStatus); !ok || status.Enabled() {
			started = true
			if err := s.wakeup.Scan(ctx); err != nil {
				incomplete = true
			}
		}
	}
	if s.cfg.RecoveryEnabled && s.cfg.ProbeEnabled && s.recovery != nil {
		if status, ok := s.recovery.(recoveryStatus); !ok || status.Enabled() {
			started = true
			if err := s.recovery.Scan(ctx); err != nil {
				incomplete = true
			}
		}
	}
	if !started {
		return jsonResponse(http.StatusOK, map[string]any{"started": false, "error": "scan_disabled"})
	}
	if incomplete {
		return jsonResponse(http.StatusOK, map[string]any{"started": true, "error": "scan_incomplete"})
	}
	return jsonResponse(http.StatusOK, map[string]any{"started": true})
}

func validJSONContentType(headers http.Header) bool {
	if headers == nil {
		// Direct unit callers do not have an HTTP transport boundary. CPA's
		// server supplies Content-Type for real requests, while nil remains a
		// compatible test/in-process invocation.
		return true
	}
	value := strings.TrimSpace(headers.Get("Content-Type"))
	if value == "" {
		return true
	}
	mediaType, _, err := mime.ParseMediaType(value)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func decodeBody(raw []byte, dst any) error {
	if len(raw) == 0 {
		return errors.New("empty request body")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("request contains trailing data")
	}
	return nil
}

func jsonResponse(status int, value any) (pluginapi.ManagementResponse, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return pluginapi.ManagementResponse{}, err
	}
	return pluginapi.ManagementResponse{StatusCode: status, Headers: http.Header{"Content-Type": []string{"application/json"}}, Body: raw}, nil
}
func isCodex(provider, typ string) bool {
	return strings.EqualFold(strings.TrimSpace(provider), "codex") || strings.EqualFold(strings.TrimSpace(typ), "codex")
}
func safeMutationError(err error) string {
	if errors.Is(err, credentials.ErrRevisionMismatch) {
		return "stale_preview"
	}
	if errors.Is(err, credentials.ErrRevisionUnavailable) || errors.Is(err, credentials.ErrPostSaveRevisionUnavailable) {
		return "revision_unavailable"
	}
	if errors.Is(err, credentials.ErrPostSaveMismatch) {
		return "post_save_mismatch"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return "save_failed"
}
func newPlanID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("plan-%d", time.Now().UnixNano())
	}
	return "plan-" + hex.EncodeToString(buf)
}

type resourceHandler struct{}

func (*resourceHandler) HandleManagement(_ context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	if req.Method != "" && req.Method != http.MethodGet {
		return jsonResponse(http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
	return pluginapi.ManagementResponse{StatusCode: http.StatusOK, Headers: http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}, Body: staticIndex}, nil
}
