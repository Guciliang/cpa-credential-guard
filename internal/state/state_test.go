package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cpa-credential-guard/internal/domain"
)

func testRecord() domain.OwnershipRecord {
	return domain.OwnershipRecord{AuthIndex: "a-1", AuthID: "id-1", FileName: "auth.json", DisabledAt: time.Unix(10, 0).UTC(), WasEnabled: true, ContentHashWithoutDisabled: "sha256:abc", PluginSaveHostRevision: "auth.json|1|2|3|/auth.json", Phase: domain.PhaseOwnedDisabled, AttemptID: "attempt-1", LastReason: "codex_quota_evidence"}
}

func TestStateRoundTripAtomicAndRestrictive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	clock := func() time.Time { return time.Unix(100, 0) }
	store, report, err := NewWithClock(dir, clock)
	if err != nil || !report.Initialized {
		t.Fatalf("store=%v report=%#v", err, report)
	}
	if err := store.Update(func(next *domain.State) error { next.Credentials["codex:a-1"] = testRecord(); return nil }); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions=%o", info.Mode().Perm())
	}
	restored, report, err := NewWithClock(dir, clock)
	if err != nil || report.RecoveredCorrupt {
		t.Fatalf("reload err=%v report=%#v", err, report)
	}
	got, ok := restored.Get("codex:a-1")
	if !ok || got.AttemptID != "attempt-1" {
		t.Fatalf("record=%#v ok=%v", got, ok)
	}
}

func TestCorruptAndIncompatibleStateIsQuarantinedAndEmpty(t *testing.T) {
	dir := t.TempDir()
	raws := []string{"{not-json", "{\"schema_version\":99,\"updated_at\":\"2026-01-01T00:00:00Z\",\"credentials\":{}}"}
	for _, raw := range raws {
		if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		store, report, err := NewWithClock(dir, func() time.Time { return time.Unix(123, 0) })
		if err != nil {
			t.Fatal(err)
		}
		if !report.RecoveredCorrupt || report.QuarantinedPath == "" || len(store.Snapshot().Credentials) != 0 {
			t.Fatalf("report=%#v state=%#v", report, store.Snapshot())
		}
		matches, _ := filepath.Glob(filepath.Join(dir, "state.json.*.corrupt"))
		if len(matches) == 0 {
			t.Fatal("missing quarantine")
		}
	}
}

func TestCorruptQuarantineHandlesClockCollision(t *testing.T) {
	dir := t.TempDir()
	clock := func() time.Time { return time.Unix(123, 0) }
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, first, err := NewWithClock(dir, clock)
	if err != nil || first.QuarantinedPath == "" {
		t.Fatalf("first report=%#v err=%v", first, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("bad-again"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, second, err := NewWithClock(dir, clock)
	if err != nil || second.QuarantinedPath == "" || second.QuarantinedPath == first.QuarantinedPath {
		t.Fatalf("second report=%#v first=%q err=%v", second, first.QuarantinedPath, err)
	}
}

func TestSymlinkStateFileIsQuarantinedWithoutFollowingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside.json")
	secret := []byte(`{"schema_version":99,"updated_at":"2026-01-01T00:00:00Z","credentials":{}}`)
	if err := os.WriteFile(target, secret, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "state.json")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	_, report, err := NewWithClock(dir, time.Now)
	if err != nil || !report.RecoveredCorrupt || report.QuarantinedPath == "" {
		t.Fatalf("report=%#v err=%v", report, err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(secret) {
		t.Fatalf("target changed: %q err=%v", got, err)
	}
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("target permissions=%o err=%v", info.Mode().Perm(), err)
	}
}

func TestMalformedOptionalObservationDoesNotQuarantineUsableState(t *testing.T) {
	dir := t.TempDir()
	goodRaw, err := json.Marshal(domain.CredentialObservation{AuthIndex: "good", IdentityHash: "sha256:good", Quota: &domain.QuotaObservation{AuthIndex: "good", IdentityHash: "sha256:good", Status: domain.QuotaAvailable}})
	if err != nil {
		t.Fatal(err)
	}
	badRaw := json.RawMessage(`{"auth_index":"bad","identity_hash":"sha256:bad","unexpected":"drop-me"}`)
	payload := map[string]any{
		"schema_version": domain.SchemaVersion,
		"updated_at":     time.Unix(100, 0).UTC(),
		"credentials":    map[string]domain.OwnershipRecord{"codex:a-1": testRecord()},
		"observations":   map[string]json.RawMessage{"codex:good": goodRaw, "codex:bad": badRaw},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, report, err := NewWithClock(dir, time.Now)
	if err != nil || report.RecoveredCorrupt {
		t.Fatalf("err=%v report=%#v", err, report)
	}
	if _, ok := store.Get("codex:a-1"); !ok {
		t.Fatal("usable ownership record was lost")
	}
	if _, ok := store.GetObservation("codex:good"); !ok {
		t.Fatal("valid observation was lost")
	}
	if _, ok := store.GetObservation("codex:bad"); ok {
		t.Fatal("malformed observation was retained")
	}
}

func TestMalformedOptionalOwnershipMetadataDoesNotQuarantineUsableState(t *testing.T) {
	dir := t.TempDir()
	recordRaw, err := json.Marshal(testRecord())
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(recordRaw, &record); err != nil {
		t.Fatal(err)
	}
	record["quota"] = "not-a-quota-object"
	record["initial_wakeup"] = map[string]any{"status": "unexpected", "identity_hash": "sha256:abc"}
	payload := map[string]any{
		"schema_version": domain.SchemaVersion,
		"updated_at":     time.Unix(100, 0).UTC(),
		"credentials":    map[string]any{"codex:a-1": record},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, report, err := NewWithClock(dir, time.Now)
	if err != nil || report.RecoveredCorrupt {
		t.Fatalf("err=%v report=%#v", err, report)
	}
	got, ok := store.Get("codex:a-1")
	if !ok {
		t.Fatal("usable ownership record was lost")
	}
	if got.Quota != nil {
		t.Fatalf("malformed quota metadata was retained: %#v", got)
	}
	if got.InitialWakeup == nil || got.InitialWakeup.Status != "unknown" {
		t.Fatalf("malformed wake metadata was not reduced to safe unknown: %#v", got)
	}
}

func TestMalformedOptionalProbeMetadataDoesNotQuarantineOwnership(t *testing.T) {
	dir := t.TempDir()
	recordRaw, err := json.Marshal(testRecord())
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(recordRaw, &record); err != nil {
		t.Fatal(err)
	}
	record["last_probe"] = map[string]any{
		"status":     "unexpected",
		"safe_error": "untrusted-upstream-detail",
	}
	payload := map[string]any{
		"schema_version": domain.SchemaVersion,
		"updated_at":     time.Unix(100, 0).UTC(),
		"credentials":    map[string]any{"codex:a-1": record},
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, report, err := NewWithClock(dir, time.Now)
	if err != nil || report.RecoveredCorrupt {
		t.Fatalf("err=%v report=%#v", err, report)
	}
	got, ok := store.Get("codex:a-1")
	if !ok || got.LastProbe == nil || got.LastProbe.Status != domain.ProbeAmbiguous || got.LastProbe.SafeError != "probe_error" {
		t.Fatalf("safe probe=%#v ok=%v", got.LastProbe, ok)
	}
}

func TestStateNeverPersistsSecretFixtures(t *testing.T) {
	dir := t.TempDir()
	store, _, err := NewWithClock(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	secret := "access-secret Authorization Bearer cookie proxy-password"
	if err := store.Update(func(next *domain.State) error { next.Credentials["codex:a-1"] = testRecord(); return nil }); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("secret fixture persisted")
	}
}

func TestStateBoundsOptionalWindowAndWakeMetadata(t *testing.T) {
	dir := t.TempDir()
	store, _, err := NewWithClock(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	windows := make([]domain.QuotaWindow, 64)
	for index := range windows {
		windows[index] = domain.QuotaWindow{Family: "primary"}
	}
	observation := domain.CredentialObservation{
		AuthIndex:     "a-1",
		IdentityHash:  "sha256:abc",
		Quota:         &domain.QuotaObservation{AuthIndex: "a-1", IdentityHash: "sha256:abc", Status: domain.QuotaAvailable, Windows: windows},
		InitialWakeup: &domain.WakeupRecord{Mode: domain.WakeupInitial, Status: "pending", IdentityHash: "sha256:abc", AttemptCount: 999},
	}
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a-1"] = observation
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := store.GetObservation("codex:a-1")
	if !ok || got.Quota == nil || len(got.Quota.Windows) != 32 || got.InitialWakeup == nil || got.InitialWakeup.AttemptCount != 3 {
		t.Fatalf("bounded observation=%#v ok=%v", got, ok)
	}
}

func TestStateDoesNotTrustIncompleteWakeSuccess(t *testing.T) {
	dir := t.TempDir()
	store, _, err := NewWithClock(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	observation := domain.CredentialObservation{
		AuthIndex:    "a-1",
		IdentityHash: "sha256:abc",
		InitialWakeup: &domain.WakeupRecord{
			Mode:         domain.WakeupInitial,
			Status:       "success",
			IdentityHash: "sha256:abc",
		},
	}
	if err := store.Update(func(next *domain.State) error {
		next.Observations["codex:a-1"] = observation
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	got, ok := store.GetObservation("codex:a-1")
	if !ok || got.InitialWakeup == nil || got.InitialWakeup.Status != "unknown" || got.InitialWakeup.SafeError != "wake_manual_review" {
		t.Fatalf("incomplete wake success was trusted: %#v ok=%v", got, ok)
	}
}

func TestStateNormalizesUntrustedProbeFamilyBeforePersistence(t *testing.T) {
	dir := t.TempDir()
	store, _, err := NewWithClock(dir, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	record := testRecord()
	record.LastProbe = &domain.ProbeSummary{Status: domain.ProbeError, SafeError: "probe_error", Windows: []domain.QuotaWindow{{Family: "response-token-secret"}}}
	if err := store.Update(func(next *domain.State) error {
		next.Credentials["codex:a-1"] = record
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "response-token-secret") {
		t.Fatalf("untrusted probe family persisted: %s", raw)
	}
	got, ok := store.Get("codex:a-1")
	if !ok || got.LastProbe == nil || got.LastProbe.Windows[0].Family != "additional" {
		t.Fatalf("record=%#v ok=%v", got, ok)
	}
}
