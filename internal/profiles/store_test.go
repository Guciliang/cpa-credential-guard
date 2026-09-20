package profiles

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cpa-credential-guard/internal/domain"
)

func TestStorePersistsNamedProfilesWithoutExposingUserinfo(t *testing.T) {
	dir := t.TempDir()
	now := time.Unix(100, 0)
	store, report, err := NewWithClock(dir, func() time.Time { return now })
	if err != nil || !report.Initialized {
		t.Fatalf("new store: report=%#v err=%v", report, err)
	}
	profile, err := store.Upsert("", "香港线路", "socks5://alice:secret@Proxy.Example:1080")
	if err != nil {
		t.Fatal(err)
	}
	if profile.ID == "" || profile.Projection.Remark != "香港线路" || profile.Projection.Endpoint != "socks5h://proxy.example:1080" {
		t.Fatalf("profile=%#v", profile)
	}
	if strings.Contains(profile.Projection.Endpoint, "secret") {
		t.Fatal("profile projection exposed proxy credentials")
	}
	store.Close()

	reopened, report, err := NewWithClock(dir, func() time.Time { return now.Add(time.Second) })
	if err != nil || report.RecoveredCorrupt {
		t.Fatalf("reopen: report=%#v err=%v", report, err)
	}
	defer reopened.Close()
	loaded, ok := reopened.Get(profile.ID)
	if !ok || loaded.Remark != "香港线路" || loaded.ProxyURL == "" {
		t.Fatalf("loaded=%#v ok=%v", loaded, ok)
	}
	matched, ok := reopened.Match("socks5://alice:secret@proxy.example:1080")
	if !ok || matched.ID != profile.ID {
		t.Fatalf("matched=%#v ok=%v", matched, ok)
	}
	if err := reopened.Delete(profile.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.Get(profile.ID); ok {
		t.Fatal("deleted profile still present")
	}
}

func TestStoreUpdatesRemarkWhileRetainingOrReplacingURL(t *testing.T) {
	store, _, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	created, err := store.Upsert("one", "线路", "http://proxy.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	retained, err := store.Save(created.ID, "新名称", nil)
	if err != nil {
		t.Fatal(err)
	}
	if retained.Remark != "新名称" || retained.ProxyURL != "http://proxy.example:8080" {
		t.Fatalf("retained=%#v", retained)
	}
	if _, err := store.Upsert(created.ID, "缺少地址", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Upsert accepted an empty replacement URL: %v", err)
	}
	blank := "  "
	retained, err = store.Save(created.ID, "再次命名", &blank)
	if err != nil || retained.ProxyURL != "http://proxy.example:8080" {
		t.Fatalf("blank update profile=%#v err=%v", retained, err)
	}
	replacementURL := "socks5://user:secret@other.example:1080"
	replaced, err := store.Save(created.ID, "新地址", &replacementURL)
	if err != nil {
		t.Fatal(err)
	}
	if replaced.ProxyURL != "socks5h://user:secret@other.example:1080" || strings.Contains(replaced.Projection.Endpoint, "secret") {
		t.Fatalf("replaced=%#v", replaced)
	}
	if _, err := store.Save("missing", "未知", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown profile error=%v", err)
	}
}

func TestStoreValidatesFallbackModesReferencesCyclesAndSafeState(t *testing.T) {
	store, _, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	backup, err := store.Upsert("backup", "备用线路", "http://backup.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	primary, err := store.Upsert("primary", "主线路", "http://primary.example:8080")
	if err != nil {
		t.Fatal(err)
	}
	mode := domain.FallbackProfile
	backupID := backup.ID
	configured, err := store.SaveWithFallback(primary.ID, primary.Remark, nil, &mode, &backupID)
	if err != nil || configured.Projection.FallbackMode != domain.FallbackProfile || configured.Projection.FallbackProfileRemark != backup.Remark || configured.Projection.FallbackState != "configured" {
		t.Fatalf("configured=%#v err=%v", configured, err)
	}
	selfID := primary.ID
	if _, err := store.SaveWithFallback(primary.ID, primary.Remark, nil, &mode, &selfID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("self fallback error=%v", err)
	}
	missingID := "missing"
	if _, err := store.SaveWithFallback(primary.ID, primary.Remark, nil, &mode, &missingID); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing fallback error=%v", err)
	}
	modeDirect := domain.FallbackDirect
	if _, err := store.SaveWithFallback(backup.ID, backup.Remark, nil, &modeDirect, nil); err != nil {
		t.Fatal(err)
	}
	backupToPrimary := primary.ID
	if _, err := store.SaveWithFallback(backup.ID, backup.Remark, nil, &mode, &backupToPrimary); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cycle fallback error=%v", err)
	}
	if err := store.MarkFallback(primary.ID, []string{"auth-b", "auth-a", "auth-a"}); err != nil {
		t.Fatal(err)
	}
	active, ok := store.Get(primary.ID)
	if !ok || active.Projection.FallbackState != "active" || len(active.FallbackAuthIndexes) != 2 || active.Projection.FallbackOriginalRemark != primary.Remark {
		t.Fatalf("active=%#v ok=%v", active, ok)
	}
	if _, err := store.SaveWithFallback(primary.ID, "主线路改名", nil, &mode, &backupID); err != nil {
		t.Fatalf("rename active fallback: %v", err)
	}
	active, _ = store.Get(primary.ID)
	if active.Projection.FallbackState != "active" || len(active.FallbackAuthIndexes) != 2 {
		t.Fatalf("active fallback was lost during rename: %#v", active.Projection)
	}
	if _, err := store.SaveWithFallback(primary.ID, active.Remark, nil, &modeDirect, nil); !errors.Is(err, ErrActiveFallback) {
		t.Fatalf("active fallback reconfiguration error=%v", err)
	}
	if err := store.Delete(primary.ID); !errors.Is(err, ErrActiveFallback) {
		t.Fatalf("active fallback delete error=%v", err)
	}
	if err := store.ClearFallback(primary.ID, []string{"auth-a"}); err != nil {
		t.Fatal(err)
	}
	partial, _ := store.Get(primary.ID)
	if partial.Projection.FallbackState != "active" || len(partial.FallbackAuthIndexes) != 1 {
		t.Fatalf("partial=%#v", partial)
	}
	if err := store.ClearFallback(primary.ID, []string{"auth-b"}); err != nil {
		t.Fatal(err)
	}
	cleared, _ := store.Get(primary.ID)
	if cleared.Projection.FallbackState != "configured" || len(cleared.FallbackAuthIndexes) != 0 {
		t.Fatalf("cleared=%#v", cleared)
	}
	if err := store.Delete(backup.ID); !errors.Is(err, ErrReferenced) {
		t.Fatalf("referenced delete error=%v", err)
	}
}

func TestStoreRejectsDuplicateRemarksAndQuarantinesCorruptCatalog(t *testing.T) {
	dir := t.TempDir()
	store, _, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Upsert("one", "线路", "http://proxy.example:8080"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Upsert("two", "线路", "http://other.example:8080"); err == nil {
		t.Fatal("duplicate remark accepted")
	}
	store.Close()

	path := filepath.Join(dir, fileName)
	if err := os.WriteFile(path, []byte(`{"schema_version":999,"updated_at":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, report, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	if !report.RecoveredCorrupt || report.QuarantinedPath == "" {
		t.Fatalf("report=%#v", report)
	}
	if _, err := os.Stat(report.QuarantinedPath); err != nil {
		t.Fatalf("quarantine file missing: %v", err)
	}
	if got := len(recovered.List()); got != 0 {
		t.Fatalf("recovered profiles=%d", got)
	}
}
