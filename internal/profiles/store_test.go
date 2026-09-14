package profiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
