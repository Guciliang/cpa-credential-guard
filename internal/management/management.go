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
	ProxyURL  *string `json:"proxy_url,omitempty"`
	Clear     bool    `json:"clear,omitempty"`
}
type ProxyPreviewRequest struct {
	AuthIndex   string        `json:"auth_index,omitempty"`
	Changes     []ProxyChange `json:"changes,omitempty"`
	AuthIndexes []string      `json:"auth_indexes,omitempty"`
	ProxyURL    *string       `json:"proxy_url,omitempty"`
	Clear       bool          `json:"clear,omitempty"`
}
type proxyApplyRequest struct {
	PlanID string `json:"plan_id"`
}
type proxyTestRequest struct {
	Proxies []string `json:"proxies"`
}

type statusResponse struct {
	Config map[string]any `json:"config"`
	State  struct {
		Available       bool `json:"available"`
		CredentialCount int  `json:"credential_count"`
	} `json:"state"`
	Credentials []domain.CredentialProjection `json:"credentials"`
	ProxyGroups []proxyGroup                  `json:"proxy_groups"`
}
type proxyGroup struct {
	Fingerprint string `json:"fingerprint"`
	Endpoint    string `json:"endpoint"`
	Count       int    `json:"count"`
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
	out := statusResponse{Config: s.cfg.EffectiveProjection(), Credentials: []domain.CredentialProjection{}, ProxyGroups: []proxyGroup{}}
	if s.store != nil {
		out.State.Available = true
		out.State.CredentialCount = len(s.store.Snapshot().Credentials)
	}
	if s.repo == nil {
		return jsonResponse(http.StatusOK, out)
	}
	entries, err := s.repo.List(ctx)
	if err != nil {
		return jsonResponse(http.StatusOK, map[string]any{"config": out.Config, "state": map[string]any{"available": false}, "credentials": []any{}, "error": "host_unavailable"})
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
		row := domain.CredentialProjection{AuthIndex: entry.AuthIndex, AuthID: entry.ID, FileName: snap.Name, Provider: entry.Provider, Label: entry.Label, Disabled: snap.Disabled, Proxy: proxy.Redact(snap.ProxyURL)}
		if s.store != nil {
			if record, ok := s.store.Get("codex:" + entry.AuthIndex); ok {
				row.Ownership = &domain.OwnershipSummary{Phase: record.Phase, DisabledAt: record.DisabledAt, ResetAt: record.ResetAt, NextCheckAt: record.NextCheckAt, BackoffLevel: record.BackoffLevel, LastReason: domain.SafeCode(record.LastReason), LastProbe: domain.SafeProbeSummary(record.LastProbe)}
			}
		}
		out.Credentials = append(out.Credentials, row)
		if row.Proxy.Configured {
			key := row.Proxy.Fingerprint
			if groups[key] == nil {
				groups[key] = &proxyGroup{Fingerprint: key, Endpoint: row.Proxy.Endpoint}
			}
			groups[key].Count++
		}
	}
	for _, group := range groups {
		out.ProxyGroups = append(out.ProxyGroups, *group)
	}
	sort.Slice(out.ProxyGroups, func(i, j int) bool {
		return out.ProxyGroups[i].Fingerprint < out.ProxyGroups[j].Fingerprint
	})
	return jsonResponse(http.StatusOK, out)
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
		changes = append(changes, ProxyChange{AuthIndex: request.AuthIndex, ProxyURL: request.ProxyURL, Clear: request.Clear})
	}
	if len(changes) == 0 && len(request.AuthIndexes) > 0 {
		for _, index := range request.AuthIndexes {
			changes = append(changes, ProxyChange{AuthIndex: index, ProxyURL: request.ProxyURL, Clear: request.Clear})
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
		if change.Clear && change.ProxyURL != nil {
			item.ErrorCode = "ambiguous_proxy_change"
			result.ErrorCode = item.ErrorCode
			results = append(results, result)
			items = append(items, item)
			continue
		}
		oldProjection := proxy.Redact(snap.ProxyURL)
		item.OldProjection = oldProjection
		result.OldEndpoint = oldProjection.Endpoint
		result.OldFingerprint = oldProjection.Fingerprint
		if change.Clear {
			item.Action = "clear"
			result.Action = "clear"
		} else {
			if change.ProxyURL == nil {
				item.ErrorCode = "proxy_url_required"
				result.ErrorCode = item.ErrorCode
				results = append(results, result)
				items = append(items, item)
				continue
			}
			validated, validateErr := proxy.Validate(*change.ProxyURL)
			if validateErr != nil {
				item.ErrorCode = "invalid_proxy"
				result.ErrorCode = item.ErrorCode
				results = append(results, result)
				items = append(items, item)
				continue
			}
			item.RawURL = validated.URL.String()
			item.Projection = validated.Projection
			if snap.ProxyURL == "" {
				item.Action = "set"
			} else {
				item.Action = "replace"
			}
			result.Action = item.Action
			result.Endpoint = item.Projection.Endpoint
			result.Fingerprint = item.Projection.Fingerprint
			result.NewEndpoint = item.Projection.Endpoint
			result.NewFingerprint = item.Projection.Fingerprint
		}
		if item.Action == "clear" {
			result.Endpoint = ""
			result.Fingerprint = ""
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
		result := domain.BatchItemResult{AuthIndex: item.AuthIndex, Action: item.Action, Endpoint: item.Projection.Endpoint, Fingerprint: item.Projection.Fingerprint, OldEndpoint: item.OldProjection.Endpoint, OldFingerprint: item.OldProjection.Fingerprint}
		if item.ErrorCode != "" {
			result.ErrorCode = item.ErrorCode
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
		result.Fingerprint = proxy.Redact(mutation.After.ProxyURL).Fingerprint
		result.NewEndpoint = result.Endpoint
		result.NewFingerprint = result.Fingerprint
		results = append(results, result)
	}
	return jsonResponse(http.StatusOK, map[string]any{"plan_id": request.PlanID, "items": results})
}

func (s *Service) test(ctx context.Context, raw []byte) (pluginapi.ManagementResponse, error) {
	if len(raw) > MaxManagementBody {
		return jsonResponse(http.StatusRequestEntityTooLarge, map[string]string{"error": "body_too_large"})
	}
	var request proxyTestRequest
	if err := decodeBody(raw, &request); err != nil || len(request.Proxies) == 0 || len(request.Proxies) > MaxBatchItems {
		return jsonResponse(http.StatusBadRequest, map[string]string{"error": "invalid_proxy_batch"})
	}
	checker := s.checkerForRequest()
	results := make([]domain.BatchItemResult, 0, len(request.Proxies))
	for _, rawProxy := range request.Proxies {
		result := checker.Check(ctx, rawProxy)
		results = append(results, domain.BatchItemResult{Endpoint: result.Projection.Endpoint, Fingerprint: result.Projection.Fingerprint, Reachable: result.Reachable, HTTPStatus: result.HTTPStatus, LatencyMS: result.Latency.Milliseconds(), OK: result.Reachable, ErrorCode: result.ErrorCode})
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
