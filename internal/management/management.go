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
type recoveryStatus interface{ Enabled() bool }

type Service struct {
	cfg          config.Config
	repo         *credentials.Repository
	store        *state.Store
	recovery     RecoveryScanner
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
	AuthIndex   string        `json:"auth_index,omitempty"`
	Changes     []ProxyChange `json:"changes,omitempty"`
	AuthIndexes []string      `json:"auth_indexes,omitempty"`
	ProfileID   string        `json:"profile_id,omitempty"`
	ProxyURL    *string       `json:"proxy_url,omitempty"` // legacy input
	Clear       bool          `json:"clear,omitempty"`
}
type proxyApplyRequest struct {
	PlanID string `json:"plan_id"`
}
type proxyTestRequest struct {
	Proxies    []string `json:"proxies,omitempty"` // retained for direct token-free tests
	ProfileIDs []string `json:"profile_ids,omitempty"`
}
type proxyProfileRequest struct {
	ID       string `json:"id,omitempty"`
	Remark   string `json:"remark"`
	ProxyURL string `json:"proxy_url"`
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
	return &Service{cfg: cfg, repo: repo, store: store, recovery: recovery, checker: proxy.NewChecker(), plans: make(map[string]plan), now: now}
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
			{Method: http.MethodGet, Path: managementPrefix + "/proxy/profiles", Description: "查看已保存的代理备注。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/profiles", Description: "保存代理备注和代理地址。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/profiles/delete", Description: "删除代理备注。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/preview", Description: "应用前验证代理批次。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/apply", Description: "应用已验证的代理计划。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/proxy/test", Description: "测试无令牌代理连通性。", Handler: handler},
			{Method: http.MethodPost, Path: managementPrefix + "/recovery/scan", Description: "扫描到期的插件所有权恢复记录。", Handler: handler},
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
	if s.repo == nil {
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
			continue
		}
		proxyProjection := proxy.Redact(snap.ProxyURL)
		if profile, ok := s.matchProfile(snap.ProxyURL); ok {
			proxyProjection.ProfileID = profile.ID
			proxyProjection.Remark = profile.Remark
		}
		row := domain.CredentialProjection{AuthIndex: entry.AuthIndex, AuthID: entry.ID, FileName: snap.Name, Provider: entry.Provider, Label: entry.Label, Disabled: snap.Disabled, Proxy: proxyProjection}
		if s.store != nil {
			if record, ok := s.store.Get("codex:" + entry.AuthIndex); ok {
				row.Ownership = &domain.OwnershipSummary{Phase: record.Phase, DisabledAt: record.DisabledAt, ResetAt: record.ResetAt, NextCheckAt: record.NextCheckAt, BackoffLevel: record.BackoffLevel, LastReason: domain.SafeCode(record.LastReason), LastProbe: domain.SafeProbeSummary(record.LastProbe)}
			}
		}
		out.Credentials = append(out.Credentials, row)
		if row.Proxy.Configured {
			key := row.Proxy.ProfileID
			if key == "" {
				key = "endpoint:" + row.Proxy.Endpoint
			}
			if groups[key] == nil {
				remark := row.Proxy.Remark
				if remark == "" {
					remark = "未命名代理"
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
	profile, err := s.profileStore.Upsert(request.ID, request.Remark, request.ProxyURL)
	if err != nil {
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

func (s *Service) preview(ctx context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	var request ProxyPreviewRequest
	if err := decodeBody(raw, &request); err != nil {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_json"})
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
		if change.Clear && (change.ProxyURL != nil || strings.TrimSpace(change.ProfileID) != "" || change.Keep) {
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
	for _, item := range items {
		if item.ErrorCode == "" {
			valid = true
			break
		}
	}
	planID := ""
	expiresAt := time.Time{}
	if valid {
		planID = newPlanID()
		expiresAt = s.now().Add(5 * time.Minute)
		p := plan{ID: planID, ExpiresAt: expiresAt, Items: items}
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
		results = append(results, result)
	}
	return jsonResponse(http.StatusOK, map[string]any{"plan_id": request.PlanID, "items": results})
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
	results := make([]domain.BatchItemResult, 0, len(request.Proxies)+len(request.ProfileIDs))
	for _, profileID := range request.ProfileIDs {
		profile, ok := s.profileStore.Get(strings.TrimSpace(profileID))
		if !ok {
			results = append(results, domain.BatchItemResult{ProfileID: strings.TrimSpace(profileID), ErrorCode: "profile_not_found"})
			continue
		}
		checkResult := checker.Check(ctx, profile.ProxyURL)
		results = append(results, domain.BatchItemResult{ProfileID: profile.ID, ProfileRemark: profile.Remark, Endpoint: checkResult.Projection.Endpoint, Reachable: checkResult.Reachable, HTTPStatus: checkResult.HTTPStatus, LatencyMS: checkResult.Latency.Milliseconds(), OK: checkResult.Reachable, ErrorCode: checkResult.ErrorCode})
	}
	for _, rawProxy := range request.Proxies {
		checkResult := checker.Check(ctx, rawProxy)
		profileID, profileRemark := "", ""
		if profile, ok := s.matchProfile(rawProxy); ok {
			profileID, profileRemark = profile.ID, profile.Remark
		}
		results = append(results, domain.BatchItemResult{ProfileID: profileID, ProfileRemark: profileRemark, Endpoint: checkResult.Projection.Endpoint, Reachable: checkResult.Reachable, HTTPStatus: checkResult.HTTPStatus, LatencyMS: checkResult.Latency.Milliseconds(), OK: checkResult.Reachable, ErrorCode: checkResult.ErrorCode})
	}
	return jsonResponse(http.StatusOK, map[string]any{"items": results})
}
func (s *Service) scan(ctx context.Context) (pluginapi.ManagementResponse, error) {
	if !s.cfg.Enabled {
		return jsonResponse(http.StatusForbidden, map[string]any{"started": false, "error": "credential_guard_disabled"})
	}
	if !s.cfg.RecoveryEnabled || !s.cfg.ProbeEnabled {
		return jsonResponse(http.StatusOK, map[string]any{"started": false, "error": "recovery_disabled"})
	}
	if s.recovery == nil {
		return jsonResponse(http.StatusOK, map[string]any{"started": false, "error": "recovery_unavailable"})
	}
	if status, ok := s.recovery.(recoveryStatus); ok && !status.Enabled() {
		return jsonResponse(http.StatusOK, map[string]any{"started": false, "error": "recovery_disabled"})
	}
	if err := s.recovery.Scan(ctx); err != nil {
		return jsonResponse(http.StatusOK, map[string]any{"started": false, "error": "scan_incomplete"})
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
