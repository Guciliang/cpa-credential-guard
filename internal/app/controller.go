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
	"cpa-credential-guard/internal/quota"
	"cpa-credential-guard/internal/recovery"
	"cpa-credential-guard/internal/state"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

type Controller struct {
	cfg         config.Config
	host        host.API
	repo        *credentials.Repository
	store       *state.Store
	recovery    *recovery.Manager
	management  *management.Service
	ctx         context.Context
	cancel      context.CancelFunc
	operations  sync.WaitGroup
	operationMu sync.Mutex
	closing     bool
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
		health := codexhealth.NewClient()
		health.Timeout = cfg.ProbeTimeout
		rCfg := recovery.Config{Enabled: cfg.RecoveryEnabled, ProbeEnabled: cfg.ProbeEnabled, ScanInterval: cfg.ScanInterval, InitialBackoff: cfg.InitialBackoff, MaxBackoff: cfg.MaxBackoff}
		c.recovery = recovery.New(store, c.repo, health, rCfg)
		if startRecovery {
			c.recovery.Start(runCtx)
		}
	}
	c.management = management.New(cfg, c.repo, c.store, c.recovery)
	c.management.SetRouteHandler(c)
	return c, nil
}

// Start begins the controller's recovery worker after the controller has been
// published as the active lifecycle instance.
func (c *Controller) Start() {
	if c == nil || c.recovery == nil {
		return
	}
	c.operationMu.Lock()
	closing := c.closing
	ctx := c.ctx
	c.operationMu.Unlock()
	if !closing {
		c.recovery.Start(ctx)
	}
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
		return
	}
	c.closing = true
	cancel := c.cancel
	c.cancel = nil
	c.operationMu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c.recovery != nil {
		c.recovery.Stop()
	}
	c.operations.Wait()
	if c.store != nil {
		_ = c.store.Close()
	}
}

// HandleUsage implements pluginapi.UsagePlugin. Classification is pure and
// callback processing is queued in a goroutine so a CPA request-completion
// callback is never blocked on disk or credential I/O.
func (c *Controller) HandleUsage(ctx context.Context, record pluginapi.UsageRecord) {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || !c.cfg.Enabled || !c.cfg.QuotaDetectionEnabled || c.repo == nil || c.store == nil {
		return
	}
	decision := quota.Classify(quota.UsageInput{Provider: record.Provider, StatusCode: record.Failure.StatusCode, Failed: record.Failed, Body: record.Failure.Body, Headers: record.ResponseHeaders, DetectHTTP429: c.cfg.DetectHTTP429, ClassifyGenericRateLimit: c.cfg.ClassifyGenericRateLimit, Now: time.Now()})
	if decision.Decision != domain.DecisionQuotaExhausted {
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
		_ = c.disableFromQuota(operationCtx, record, decision)
	}()
}

// ProcessUsage is synchronous for fake-host and end-to-end tests.
func (c *Controller) ProcessUsage(ctx context.Context, record pluginapi.UsageRecord) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c == nil || !c.cfg.Enabled || !c.cfg.QuotaDetectionEnabled || c.repo == nil || c.store == nil {
		return errors.New("credential guard is inert")
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

func (c *Controller) disableFromQuota(ctx context.Context, record pluginapi.UsageRecord, decision domain.QuotaDecision) error {
	index, entry, err := c.repo.Resolve(ctx, record.AuthID, record.AuthIndex)
	if err != nil {
		return err
	}
	if !isCodex(entry.Provider, entry.Type) {
		return nil
	}
	return c.repo.WithLock(ctx, index, func() error {
		snap, err := c.repo.Snapshot(ctx, index)
		if err != nil {
			return err
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
		if existing, ok := c.store.Get(key); ok && (existing.Phase == domain.PhaseRestorePending || existing.Phase == domain.PhaseProbePending || existing.Phase == domain.PhaseManualReview) {
			return nil
		}
		guard := credentials.Guard{ContentHashWithoutDisabled: snap.ContentHashWithoutDisabled}
		if snap.Revision != "" {
			guard.HostRevision = snap.Revision
		}
		result, err := c.repo.SetDisabledLocked(ctx, index, true, guard)
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
		if next.IsZero() {
			backoff := c.cfg.InitialBackoff
			if backoff <= 0 {
				backoff = config.DefaultInitialBackoff
			}
			next = now.Add(backoff)
		}
		recordState := domain.OwnershipRecord{AuthIndex: index, AuthID: record.AuthID, FileName: result.Before.Name, DisabledAt: now, WasEnabled: true, ContentHashWithoutDisabled: result.Before.ContentHashWithoutDisabled, PluginSaveHostRevision: result.After.Revision.String(), Phase: domain.PhaseOwnedDisabled, AttemptID: newAttemptID(), ResetAt: decision.ResetAt, NextCheckAt: next, LastReason: decision.Reason, LastProbe: nil}
		if recordState.AuthID == "" {
			recordState.AuthID = entry.ID
		}
		return c.store.Update(func(nextState *domain.State) error {
			nextState.Credentials[key] = recordState
			return nil
		})
	})
}

func isCodex(provider, typ string) bool {
	return strings.EqualFold(strings.TrimSpace(provider), "codex") || strings.EqualFold(strings.TrimSpace(typ), "codex")
}
func newAttemptID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z07:00")
	}
	return "attempt-" + hex.EncodeToString(buf)
}
