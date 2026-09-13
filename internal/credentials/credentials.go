// Package credentials owns fresh Host get -> one-field mutation -> save
// transactions, non-reversible content revisions, and per-auth serialization.
package credentials

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"cpa-credential-guard/internal/host"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const MaxCredentialBytes = 2 << 20

var (
	ErrRevisionMismatch            = errors.New("credential changed since preview or ownership observation")
	ErrRevisionUnavailable         = errors.New("credential runtime revision unavailable")
	ErrPostSaveRevisionUnavailable = errors.New("credential post-save runtime revision unavailable")
	ErrPostSaveMismatch            = errors.New("credential post-save value could not be verified")
	ErrNotCodex                    = errors.New("credential is not codex")
)

type RuntimeRevision string

type Snapshot struct {
	AuthIndex                  string
	AuthID                     string
	Name                       string
	Path                       string
	JSON                       json.RawMessage
	Disabled                   bool
	ProxyURL                   string
	Provider                   string
	Runtime                    pluginapi.HostAuthFileEntry
	RuntimeOK                  bool
	Revision                   RuntimeRevision
	ContentHashWithoutDisabled string
	FullHash                   string
}

type Guard struct {
	ContentHashWithoutDisabled string
	FullHash                   string
	HostRevision               RuntimeRevision
	RequireRuntime             bool
}

type MutationResult struct {
	Before  Snapshot
	After   Snapshot
	Changed bool
}

type Repository struct {
	host    host.API
	locksMu sync.Mutex
	locks   map[string]chan struct{}
}

func NewRepository(api host.API) *Repository {
	return &Repository{host: api, locks: make(map[string]chan struct{})}
}
func (r *Repository) Host() host.API { return r.host }

func (r *Repository) lockFor(index string) chan struct{} {
	r.locksMu.Lock()
	defer r.locksMu.Unlock()
	if r.locks[index] == nil {
		r.locks[index] = make(chan struct{}, 1)
		r.locks[index] <- struct{}{}
	}
	return r.locks[index]
}

func (r *Repository) WithLock(ctx context.Context, index string, fn func() error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(index) == "" {
		return errors.New("auth index is required")
	}
	lock := r.lockFor(index)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-lock:
	}
	defer func() { lock <- struct{}{} }()
	return fn()
}

func (r *Repository) List(ctx context.Context) ([]pluginapi.HostAuthFileEntry, error) {
	if r == nil || r.host == nil {
		return nil, errors.New("host adapter unavailable")
	}
	return r.host.List(ctx)
}

func (r *Repository) Resolve(ctx context.Context, authID, authIndex string) (string, pluginapi.HostAuthFileEntry, error) {
	if authIndex != "" {
		entries, err := r.List(ctx)
		if err != nil {
			return "", pluginapi.HostAuthFileEntry{}, err
		}
		var match pluginapi.HostAuthFileEntry
		count := 0
		for _, entry := range entries {
			if entry.AuthIndex != authIndex {
				continue
			}
			count++
			if authID != "" {
				if entry.ID == "" || entry.ID != authID {
					return "", pluginapi.HostAuthFileEntry{}, errors.New("auth id did not match auth index")
				}
			}
			match = entry
		}
		if count == 0 {
			return "", pluginapi.HostAuthFileEntry{}, fmt.Errorf("auth index %q was not found", authIndex)
		}
		if count != 1 {
			return "", pluginapi.HostAuthFileEntry{}, errors.New("auth index did not resolve uniquely")
		}
		return authIndex, match, nil
	}
	if authID == "" {
		return "", pluginapi.HostAuthFileEntry{}, errors.New("auth id or auth index is required")
	}
	entries, err := r.List(ctx)
	if err != nil {
		return "", pluginapi.HostAuthFileEntry{}, err
	}
	var match pluginapi.HostAuthFileEntry
	count := 0
	for _, entry := range entries {
		if entry.ID != authID {
			continue
		}
		match = entry
		count++
	}
	if count != 1 || !isCodexEntry(match) || strings.TrimSpace(match.AuthIndex) == "" {
		return "", pluginapi.HostAuthFileEntry{}, fmt.Errorf("auth id did not resolve uniquely")
	}
	return match.AuthIndex, match, nil
}

func isCodexEntry(entry pluginapi.HostAuthFileEntry) bool {
	return strings.EqualFold(strings.TrimSpace(entry.Provider), "codex") || strings.EqualFold(strings.TrimSpace(entry.Type), "codex")
}

func (r *Repository) Snapshot(ctx context.Context, index string) (Snapshot, error) {
	if r == nil || r.host == nil {
		return Snapshot{}, errors.New("host adapter unavailable")
	}
	response, err := r.host.Get(ctx, index)
	if err != nil {
		return Snapshot{}, err
	}
	if response.AuthIndex != "" && response.AuthIndex != index {
		return Snapshot{}, errors.New("host.auth.get returned a different auth index")
	}
	if len(response.JSON) == 0 || len(response.JSON) > MaxCredentialBytes {
		return Snapshot{}, errors.New("credential JSON is empty or too large")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(response.JSON, &fields); err != nil || fields == nil {
		return Snapshot{}, errors.New("credential JSON is not an object")
	}
	runtime, runtimeErr := r.host.GetRuntime(ctx, index)
	snap := Snapshot{AuthIndex: index, Name: response.Name, Path: response.Path, JSON: append(json.RawMessage(nil), response.JSON...)}
	if runtimeErr == nil {
		if runtime.Auth.AuthIndex != index {
			return Snapshot{}, errors.New("host.auth.get_runtime returned a different or empty auth index")
		}
		if snap.Name != "" && runtime.Auth.Name != "" && snap.Name != runtime.Auth.Name {
			return Snapshot{}, errors.New("host.auth.get and get_runtime resolved different files")
		}
		if snap.Path != "" && runtime.Auth.Path != "" && snap.Path != runtime.Auth.Path {
			return Snapshot{}, errors.New("host.auth.get and get_runtime resolved different paths")
		}
		if snap.Name == "" {
			snap.Name = runtime.Auth.Name
		}
	}
	if strings.TrimSpace(snap.Name) == "" {
		return Snapshot{}, errors.New("credential file name is unavailable")
	}
	if strings.ContainsAny(snap.Name, "/\\\\") || !strings.HasSuffix(strings.ToLower(snap.Name), ".json") {
		return Snapshot{}, errors.New("credential file name is not a JSON file")
	}
	snap.Disabled = boolField(fields, "disabled")
	snap.ProxyURL = stringField(fields, "proxy_url")
	snap.ContentHashWithoutDisabled = HashWithoutField(response.JSON, "disabled")
	snap.FullHash = HashJSON(response.JSON)
	if runtimeErr == nil {
		snap.Runtime = runtime.Auth
		snap.AuthID = runtime.Auth.ID
		snap.RuntimeOK = true
		snap.Revision = RevisionOf(runtime.Auth)
	}
	return snap, nil
}

// MutateAndSave performs exactly one fresh get, one top-level field mutation,
// and one Host save. Guard checks happen after that fresh get and before save.
func (r *Repository) MutateAndSave(ctx context.Context, index, field string, value json.RawMessage, clear bool, guard Guard) (MutationResult, error) {
	var result MutationResult
	if err := r.WithLock(ctx, index, func() error {
		var err error
		result, err = r.MutateAndSaveLocked(ctx, index, field, value, clear, guard)
		return err
	}); err != nil {
		return result, err
	}
	return result, nil
}

// MutateAndSaveLocked is the same transaction for callers that already hold
// Repository.WithLock across a larger state-machine operation.
func (r *Repository) MutateAndSaveLocked(ctx context.Context, index, field string, value json.RawMessage, clear bool, guard Guard) (MutationResult, error) {
	var result MutationResult
	if field != "disabled" && field != "proxy_url" {
		return result, errors.New("unsupported credential field")
	}
	before, err := r.Snapshot(ctx, index)
	if err != nil {
		return result, err
	}
	result.Before = before
	if !before.RuntimeOK || before.Revision == "" {
		return result, ErrRevisionUnavailable
	}
	if err := checkGuard(before, guard); err != nil {
		return result, err
	}
	updated, changed, err := MutateTopLevel(before.JSON, field, value, clear)
	if err != nil {
		return result, err
	}
	if !changed {
		result.After = before
		return result, nil
	}
	if _, err := r.host.Save(ctx, pluginapi.HostAuthSaveRequest{Name: before.Name, JSON: updated}); err != nil {
		return result, err
	}
	result.Changed = true
	// Runtime is read after save so ownership/recovery can bind to the Host's
	// own file/runtime revision rather than inventing a CAS token. A non-empty
	// tuple is not enough: it must also differ from the pre-save tuple, or a
	// stale Host response could make an unverified mutation look successful.
	after, err := r.Snapshot(ctx, index)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrPostSaveRevisionUnavailable, err)
	}
	result.After = after
	if !after.RuntimeOK || after.Revision == "" || after.Revision == before.Revision {
		return result, ErrPostSaveRevisionUnavailable
	}
	if !postSaveValueMatches(after, field, value, clear) {
		return result, ErrPostSaveMismatch
	}
	return result, nil
}

func (r *Repository) SetDisabled(ctx context.Context, index string, enabled bool, guard Guard) (MutationResult, error) {
	value, _ := json.Marshal(enabled)
	return r.MutateAndSave(ctx, index, "disabled", value, false, guard)
}
func (r *Repository) SetDisabledLocked(ctx context.Context, index string, enabled bool, guard Guard) (MutationResult, error) {
	value, _ := json.Marshal(enabled)
	return r.MutateAndSaveLocked(ctx, index, "disabled", value, false, guard)
}
func (r *Repository) SetProxy(ctx context.Context, index, proxyURL string, clear bool, guard Guard) (MutationResult, error) {
	var value json.RawMessage
	if !clear {
		raw, _ := json.Marshal(proxyURL)
		value = raw
	}
	return r.MutateAndSave(ctx, index, "proxy_url", value, clear, guard)
}
func (r *Repository) SetProxyLocked(ctx context.Context, index, proxyURL string, clear bool, guard Guard) (MutationResult, error) {
	var value json.RawMessage
	if !clear {
		raw, _ := json.Marshal(proxyURL)
		value = raw
	}
	return r.MutateAndSaveLocked(ctx, index, "proxy_url", value, clear, guard)
}

func postSaveValueMatches(s Snapshot, field string, value json.RawMessage, clear bool) bool {
	if clear {
		switch field {
		case "proxy_url":
			return s.ProxyURL == ""
		case "disabled":
			return !s.Disabled
		default:
			return false
		}
	}
	switch field {
	case "disabled":
		var expected bool
		if err := json.Unmarshal(value, &expected); err != nil {
			return false
		}
		return s.Disabled == expected
	case "proxy_url":
		var expected string
		if err := json.Unmarshal(value, &expected); err != nil {
			return false
		}
		return s.ProxyURL == expected
	default:
		return false
	}
}

func checkGuard(s Snapshot, guard Guard) error {
	if guard.ContentHashWithoutDisabled != "" && s.ContentHashWithoutDisabled != guard.ContentHashWithoutDisabled {
		return ErrRevisionMismatch
	}
	if guard.FullHash != "" && s.FullHash != guard.FullHash {
		return ErrRevisionMismatch
	}
	if guard.HostRevision != "" {
		if !s.RuntimeOK || s.Revision == "" {
			return ErrRevisionUnavailable
		}
		if s.Revision != guard.HostRevision {
			return ErrRevisionMismatch
		}
	}
	if guard.RequireRuntime && (!s.RuntimeOK || s.Revision == "") {
		return ErrRevisionUnavailable
	}
	return nil
}

// MutateTopLevel preserves every non-target JSON value semantically and
// rejects non-object credential payloads. It is the single owner of field
// preserving mutations for disabled and proxy_url.
func MutateTopLevel(raw []byte, field string, value json.RawMessage, clear bool) ([]byte, bool, error) {
	if len(raw) == 0 || len(raw) > MaxCredentialBytes {
		return nil, false, errors.New("credential JSON is empty or too large")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		return nil, false, errors.New("credential JSON must be a top-level object")
	}
	before := cloneRawMap(object)
	if clear {
		delete(object, field)
	} else {
		if len(value) == 0 || !json.Valid(value) {
			return nil, false, errors.New("mutation value must be valid JSON")
		}
		object[field] = append(json.RawMessage(nil), value...)
	}
	changed := !semanticRawMapEqual(before, object)
	if !changed {
		return append([]byte(nil), raw...), false, nil
	}
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, false, err
	}
	// Verify the requested field is the only semantic difference. This catches
	// accidental whole-document replacement if this helper is edited later.
	for key, old := range before {
		if key == field {
			continue
		}
		if !jsonSemanticEqual(old, object[key]) {
			return nil, false, errors.New("mutation changed an unrelated credential field")
		}
	}
	for key := range object {
		if key != field {
			if _, ok := before[key]; !ok {
				return nil, false, errors.New("mutation added an unrelated credential field")
			}
		}
	}
	return encoded, true, nil
}

func HashWithoutField(raw []byte, field string) string {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return ""
	}
	delete(object, field)
	encoded, err := json.Marshal(object)
	if err != nil {
		return ""
	}
	return HashBytes(encoded)
}
func HashJSON(raw []byte) string {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return ""
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return ""
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return HashBytes(encoded)
}
func HashBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func RevisionOf(entry pluginapi.HostAuthFileEntry) RuntimeRevision {
	// A name alone is not a reliable file revision. At least one size or
	// timestamp must be available, and the tuple is stable across restarts.
	if entry.Size == 0 && entry.ModTime.IsZero() && entry.UpdatedAt.IsZero() {
		return ""
	}
	return RuntimeRevision(fmt.Sprintf("%s|%d|%d|%d|%s", entry.Name, entry.Size, entry.ModTime.UnixNano(), entry.UpdatedAt.UnixNano(), entry.Path))
}
func (r RuntimeRevision) String() string { return string(r) }

func boolField(fields map[string]json.RawMessage, key string) bool {
	var v bool
	_ = json.Unmarshal(fields[key], &v)
	return v
}
func stringField(fields map[string]json.RawMessage, key string) string {
	var v string
	_ = json.Unmarshal(fields[key], &v)
	return v
}
func cloneRawMap(in map[string]json.RawMessage) map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(in))
	for k, v := range in {
		out[k] = append(json.RawMessage(nil), v...)
	}
	return out
}
func semanticRawMapEqual(a, b map[string]json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !jsonSemanticEqual(v, b[k]) {
			return false
		}
	}
	return true
}
func jsonSemanticEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return bytes.Equal(bytes.TrimSpace(a), bytes.TrimSpace(b))
	}
	return reflect.DeepEqual(x, y)
}

// Projection extracts only the safe proxy projection through the supplied
// function. The repository itself never returns proxy URL values to callers
// outside the mutation/status boundary.
func ProxyURLFromJSON(raw []byte) (string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", err
	}
	return stringField(fields, "proxy_url"), nil
}
