// Package app wires the pure domain helpers to the CPA lifecycle without
// declaring any scheduler, router, executor, interceptor, or retry capability.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"cpa-credential-guard/internal/codexhealth"
	"cpa-credential-guard/internal/config"
	"cpa-credential-guard/internal/credentials"
	"cpa-credential-guard/internal/domain"
	"cpa-credential-guard/internal/host"
	"cpa-credential-guard/internal/management"
	"cpa-credential-guard/internal/profiles"
	"cpa-credential-guard/internal/quota"
	"cpa-credential-guard/internal/recovery"
	"cpa-credential-guard/internal/state"
	"cpa-credential-guard/internal/wakeup"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type Controller struct {
	cfg          config.Config
	host         host.API
	repo         *credentials.Repository
	store        *state.Store
	profileStore *profiles.Store
	recovery     *recovery.Manager
	wakeup       *wakeup.Manager
	management   *management.Service
	ctx          context.Context
	cancel       context.CancelFunc
	operations   sync.WaitGroup
	scanWG       sync.WaitGroup
	operationMu  sync.Mutex
	closing      bool
	scanCancel   context.CancelFunc
}

func New(ctx context.Context, cfg config.Config, api host.API) (*Controller, error) {
	return newController(ctx, cfg, api, true)
}

// NewStopped constructs a fully validated controller without starting its
// recovery worker. Lifecycle callers use it to build a replacement before
// quiescing the current controller, which prevents overlapping workers during
// reconfiguration while preserving the old controller on construction error.
func NewStopped(ctx context.Context, cfg config.Config, api host.API) (*Controller, error) {
	return newController(ctx, cfg, api, false)
}

func newController(ctx context.Context, cfg config.Config, api host.API, startRecovery bool) (*Controller, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	c := &Controller{cfg: cfg, host: api, ctx: runCtx, cancel: cancel}
	if api != nil {
		c.repo = credentials.NewRepository(api)
	}
	if cfg.Enabled {
		if err := config.ValidateStateDir(cfg.StateDir); err != nil {
			cancel()
			return c, err
		}
		store, _, err := state.New(cfg.StateDir)
		if err != nil {
			cancel()
			return c, err
		}
		c.store = store
		profileStore, _, profileErr := profiles.New(cfg.StateDir)
		if profileErr != nil {
			_ = store.Close()
			cancel()
			return c, profileErr
		}
		c.profileStore = profileStore
		health := codexhealth.NewClient()
		health.Timeout = cfg.ProbeTimeout
		rCfg := recovery.Config{Enabled: cfg.RecoveryEnabled, ProbeEnabled: cfg.ProbeEnabled, ScanInterval: cfg.ScanInterval, InitialBackoff: cfg.InitialBackoff, MaxBackoff: cfg.MaxBackoff}
		c.recovery = recovery.New(store, c.repo, health, rCfg)
		wakeClient := codexhealth.NewClient()
		wakeClient.Timeout = cfg.ProbeTimeout
		wakeCfg := wakeup.Config{Enabled: cfg.Enabled, InitialEnabled: cfg.InitialWakeupEnabled, ResetEnabled: cfg.ResetWakeupEnabled, ScanInterval: cfg.ScanInterval, InitialBackoff: cfg.InitialBackoff, MaxBackoff: cfg.MaxBackoff, Model: cfg.WakeupModel, ReasoningEffort: cfg.WakeupReasoningEffort}
		c.wakeup = wakeup.New(store, c.repo, wakeClient, wakeCfg)
		if startRecovery {
			c.startScanCoordinator()
		}
	}
	c.management = management.New(cfg, c.repo, c.store, c.recovery)
	c.management.SetWakeupScanner(c.wakeup)
	c.management.SetProfileStore(c.profileStore)
	c.management.SetRouteHandler(c)
	return c, nil
}

// Start begins one shared scan coordinator after the controller has been
// published as the active lifecycle instance. Recovery and both wake-up modes
// must share the configured interval so one tick cannot fan out duplicate
// credential reads through independent timers.
func (c *Controller) Start() {
	if c == nil || (c.recovery == nil && c.wakeup == nil) {
		return
	}
	c.startScanCoordinator()
}

func (c *Controller) startScanCoordinator() {
	c.operationMu.Lock()
	if c.closing || c.scanCancel != nil || (c.recovery == nil && c.wakeup == nil) {
		c.operationMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(c.ctx)
	c.scanCancel = cancel
	interval := c.cfg.ScanInterval
	if interval < config.MinimumScanInterval {
		interval = config.MinimumScanInterval
	}
	c.scanWG.Add(1)
	c.operationMu.Unlock()
	go func() {
		defer c.scanWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Run the consuming reset wake before recovery's read-only probe.
				// Recovery may retire the ownership record or replace its reset
				// metadata at the same boundary; wake eligibility must see the
				// persisted window that made this request due. Initial wake remains
				// independently gated and only considers enabled credentials.
				if c.wakeup != nil {
					_ = c.wakeup.Scan(ctx)
				}
				if c.recovery != nil {
					_ = c.recovery.Scan(ctx)
				}
			}
		}
	}()
}

func (c *Controller) Config() config.Config           { return c.cfg }
func (c *Controller) Management() *management.Service { return c.management }
func (c *Controller) HandleManagement(ctx context.Context, req pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
	if c == nil || c.management == nil {
		return pluginapi.ManagementResponse{StatusCode: http.StatusServiceUnavailable}, nil
	}
	c.operationMu.Lock()
	if c.closing {
		c.operationMu.Unlock()
		return pluginapi.ManagementResponse{StatusCode: http.StatusServiceUnavailable}, nil
	}
	c.operations.Add(1)
	c.operationMu.Unlock()
	defer c.operations.Done()
	return c.management.HandleManagement(ctx, req)
}
func (c *Controller) Shutdown() {
	if c == nil {
		return
	}
	c.operationMu.Lock()
	if c.closing {
		c.operationMu.Unlock()
		c.operations.Wait()
		c.scanWG.Wait()
		return
	}
	c.closing = true
	cancel := c.cancel
	c.cancel = nil
	scanCancel := c.scanCancel
	c.scanCancel = nil
	c.operationMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if scanCancel != nil {
		scanCancel()
	}
	c.scanWG.Wait()
	c.operations.Wait()
	if c.store != nil {
		_ = c.store.Close()
	}
	if c.profileStore != nil {
		_ = c.profileStore.Close()
	}
}

// HandleUsage implements pluginapi.UsagePlugin. Classification is pure and
// callback processing is queued in a goroutine so a CPA request-completion
// callback is never blocked on disk or credential I/O.
func (c *Controller) HandleUsage(ctx context.Context, record pluginapi.UsageRecord) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || !c.cfg.Enabled || c.repo == nil || c.store == nil {
		return
	}
	decision := quota.Classify(quota.UsageInput{Provider: record.Provider, StatusCode: record.Failure.StatusCode, Failed: record.Failed, Body: record.Failure.Body, Headers: record.ResponseHeaders, DetectHTTP429: c.cfg.DetectHTTP429, ClassifyGenericRateLimit: c.cfg.ClassifyGenericRateLimit, Now: time.Now()})
	// A successful generated request is normal-use evidence. A failed Codex
	// request is also recorded as an ambiguous outcome so an uncertain request
	// cannot immediately trigger another consuming wake-up. The failure body is
	// never persisted or surfaced.
	shouldRecordUsage := record.Generate || record.Failed
	// UsagePlugin receives records for every provider. Only Codex usage is
	// relevant to Credential Guard; skipping other providers here avoids a
	// needless Host lookup (and an error) while preserving quota classification.
	if shouldRecordUsage && strings.TrimSpace(record.Provider) != "" && !isCodex(record.Provider, "") {
		shouldRecordUsage = false
	}
	shouldDisable := c.cfg.QuotaDetectionEnabled && decision.Decision == domain.DecisionQuotaExhausted
	if !shouldRecordUsage && !shouldDisable {
		return
	}
	c.operationMu.Lock()
	if c.closing {
		c.operationMu.Unlock()
		return
	}
	c.operations.Add(1)
	c.operationMu.Unlock()
	go func() {
		defer c.operations.Done()
		operationCtx := c.ctx
		if operationCtx == nil {
			operationCtx = context.Background()
		}
		if shouldRecordUsage {
			_ = c.recordUsageOutcome(operationCtx, record)
		}
		if shouldDisable {
			_ = c.disableFromQuota(operationCtx, record, decision)
		}
	}()
}

// ProcessUsage is synchronous for fake-host and end-to-end tests.
func (c *Controller) ProcessUsage(ctx context.Context, record pluginapi.UsageRecord) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || !c.cfg.Enabled || c.repo == nil || c.store == nil {
		return errors.New("credential guard is inert")
	}
	if (record.Generate || record.Failed) && (strings.TrimSpace(record.Provider) == "" || isCodex(record.Provider, "")) {
		if err := c.recordUsageOutcome(ctx, record); err != nil {
			return err
		}
	}
	if !c.cfg.QuotaDetectionEnabled {
		return nil
	}
	decision := quota.Classify(quota.UsageInput{Provider: record.Provider, StatusCode: record.Failure.StatusCode, Failed: record.Failed, Body: record.Failure.Body, Headers: record.ResponseHeaders, DetectHTTP429: c.cfg.DetectHTTP429, ClassifyGenericRateLimit: c.cfg.ClassifyGenericRateLimit, Now: time.Now()})
	if decision.Decision != domain.DecisionQuotaExhausted {
		return nil
	}
	c.operationMu.Lock()
	if c.closing {
		c.operationMu.Unlock()
		return errors.New("credential guard is shutting down")
	}
	c.operations.Add(1)
	c.operationMu.Unlock()
	defer c.operations.Done()
	return c.disableFromQuota(ctx, record, decision)
}

func (c *Controller) recordActualUsage(ctx context.Context, record pluginapi.UsageRecord) error {
	return c.recordUsageOutcome(ctx, record)
}

func (c *Controller) recordUsageOutcome(ctx context.Context, record pluginapi.UsageRecord) error {
	if c == nil || c.repo == nil || c.store == nil || (!record.Generate && !record.Failed) {
		return nil
	}
	index, entry, err := c.repo.Resolve(ctx, record.AuthID, record.AuthIndex)
	if err != nil {
		return err
	}
	if !isCodex(entry.Provider, entry.Type) {
		return nil
	}
	if strings.TrimSpace(record.AuthIndex) != "" && strings.TrimSpace(record.AuthIndex) != index {
		return nil
	}
	if strings.TrimSpace(record.AuthID) != "" && strings.TrimSpace(record.AuthID) != strings.TrimSpace(entry.ID) {
		return nil
	}
	return c.repo.WithLock(ctx, index, func() error {
		snap, err := c.repo.Snapshot(ctx, index)
		if err != nil {
			return err
		}
		defer wipeCredentialJSON(snap.JSON)
		// Resolve was performed before acquiring the per-auth lock. Re-check the
		// request identity against the fresh snapshot so a replacement between
		// those operations cannot turn an old CPA UsageRecord into evidence for
		// the new credential occupying the same auth index.
		if snap.AuthIndex != index || (record.AuthIndex != "" && strings.TrimSpace(record.AuthIndex) != snap.AuthIndex) || (record.AuthID != "" && (snap.Runtime.ID == "" || strings.TrimSpace(record.AuthID) != strings.TrimSpace(snap.Runtime.ID))) {
			return nil
		}
		at := record.RequestedAt
		if at.IsZero() {
			at = time.Now().UTC()
		}
		return c.store.Update(func(next *domain.State) error {
			if next.Observations == nil {
				next.Observations = map[string]domain.CredentialObservation{}
			}
			key := "codex:" + index
			observation := next.Observations[key]
			if observation.IdentityHash != "" && observation.IdentityHash != snap.ContentHashWithoutDisabled {
				observation.LastHealthCheck = nil
				observation.Quota = nil
				observation.InitialWakeup = nil
				observation.ResetWakeup = nil
				observation.Usage = nil
			}
			if observation.Quota == nil {
				if recordState, ok := next.Credentials[key]; ok && recordState.Quota != nil && recordState.Quota.IdentityHash == snap.ContentHashWithoutDisabled {
					observation.Quota = recordState.Quota
				}
			}
			observation.AuthIndex = index
			observation.IdentityHash = snap.ContentHashWithoutDisabled
			usageStatus := domain.UsageRequestFailed
			postReset := false
			if !record.Failed && record.Generate {
				usageStatus = domain.UsageNormal
				if observation.Quota != nil && observation.Quota.IdentityHash == snap.ContentHashWithoutDisabled && !observation.Quota.ResetAt.IsZero() {
					postReset = !at.Before(observation.Quota.ResetAt)
				}
			}
			observation.Usage = &domain.UsageObservation{AuthIndex: index, IdentityHash: snap.ContentHashWithoutDisabled, Status: usageStatus, PostReset: postReset, LastUsedAt: at.UTC()}
			next.Observations[key] = observation
			return nil
		})
	})
}

func (c *Controller) disableFromQuota(ctx context.Context, record pluginapi.UsageRecord, decision domain.QuotaDecision) error {
	index, entry, err := c.repo.Resolve(ctx, record.AuthID, record.AuthIndex)
	if err != nil {
		return err
	}
	if !isCodex(entry.Provider, entry.Type) {
		return nil
	}
	if strings.TrimSpace(record.AuthIndex) != "" && strings.TrimSpace(record.AuthIndex) != index {
		return nil
	}
	if strings.TrimSpace(record.AuthID) != "" && strings.TrimSpace(record.AuthID) != strings.TrimSpace(entry.ID) {
		return nil
	}
	return c.repo.WithLock(ctx, index, func() error {
		snap, err := c.repo.Snapshot(ctx, index)
		if err != nil {
			return err
		}
		defer wipeCredentialJSON(snap.JSON)
		// Resolve happened before the per-auth lock; reject a stale usage event
		// if the Host now exposes a different credential at this index.
		if snap.AuthIndex != index || (record.AuthIndex != "" && strings.TrimSpace(record.AuthIndex) != snap.AuthIndex) || (record.AuthID != "" && (snap.Runtime.ID == "" || strings.TrimSpace(record.AuthID) != strings.TrimSpace(snap.Runtime.ID))) {
			return nil
		}
		if snap.Disabled {
			return nil
		}
		// A successful save without a usable Host runtime/file revision would
		// leave a native disable that cannot be tied to durable ownership. Fail
		// closed before writing in that case.
		if !snap.RuntimeOK || snap.Revision == "" {
			return credentials.ErrRevisionUnavailable
		}
		key := "codex:" + index
		if existing, ok := c.store.Get(key); ok {
			// An existing ownership record means this identity has already been
			// through the plugin's guarded disable lifecycle. In particular, do
			// not re-disable a credential that a user or recovery flow has since
			// enabled; the next guarded scan must observe that manual change.
			if existing.ContentHashWithoutDisabled != snap.ContentHashWithoutDisabled ||
				(existing.AuthID != "" && entry.ID != "" && existing.AuthID != entry.ID) {
				return nil
			}
			return nil
		}
		guard := credentials.Guard{ContentHashWithoutDisabled: snap.ContentHashWithoutDisabled}
		if snap.Revision != "" {
			guard.HostRevision = snap.Revision
		}
		result, err := c.repo.SetDisabledLocked(ctx, index, true, guard)
		defer wipeCredentialJSON(result.Before.JSON)
		defer wipeCredentialJSON(result.After.JSON)
		if err != nil {
			return err
		}
		if !result.Changed {
			return nil
		}
		if !result.After.RuntimeOK || result.After.Revision == "" {
			return errors.New("host runtime revision unavailable after disable")
		}
		now := time.Now().UTC()
		next := decision.ResetAt
		if next.IsZero() || !next.After(now) {
			backoff := c.cfg.InitialBackoff
			if backoff <= 0 {
				backoff = config.DefaultInitialBackoff
			}
			next = now.Add(backoff)
		}
		recordState := domain.OwnershipRecord{AuthIndex: index, AuthID: record.AuthID, FileName: result.Before.Name, DisabledAt: now, WasEnabled: true, ContentHashWithoutDisabled: result.Before.ContentHashWithoutDisabled, PluginSaveHostRevision: result.After.Revision.String(), Phase: domain.PhaseOwnedDisabled, AttemptID: newAttemptID(), ResetAt: decision.ResetAt, NextCheckAt: next, LastReason: decision.Reason, LastProbe: nil, Quota: &domain.QuotaObservation{AuthIndex: index, IdentityHash: result.Before.ContentHashWithoutDisabled, Status: domain.QuotaExhausted, ResetAt: decision.ResetAt, CheckedAt: now, SafeError: "quota_exhausted", Windows: decision.Windows}}
		if recordState.AuthID == "" {
			recordState.AuthID = entry.ID
		}
		return c.store.Update(func(nextState *domain.State) error {
			nextState.Credentials[key] = recordState
			if nextState.Observations == nil {
				nextState.Observations = map[string]domain.CredentialObservation{}
			}
			observation := nextState.Observations[key]
			if observation.IdentityHash != "" && observation.IdentityHash != result.Before.ContentHashWithoutDisabled {
				observation = domain.CredentialObservation{}
			}
			observation.AuthIndex = index
			observation.IdentityHash = result.Before.ContentHashWithoutDisabled
			observation.Quota = recordState.Quota
			nextState.Observations[key] = observation
			return nil
		})
	})
}

func isCodex(provider, typ string) bool {
	return strings.EqualFold(strings.TrimSpace(provider), "codex") || strings.EqualFold(strings.TrimSpace(typ), "codex")
}

func wipeCredentialJSON(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func newAttemptID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z07:00")
	}
	return "attempt-" + hex.EncodeToString(buf)
}
