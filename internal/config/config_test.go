package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseDefaultsAreConservative(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enabled {
		t.Fatal("empty config must be disabled")
	}
	if cfg.ProbeProvider != "codex" || cfg.DetectHTTP429 != true || cfg.ClassifyGenericRateLimit || cfg.InitialWakeupEnabled || cfg.ResetWakeupEnabled || cfg.WakeupModel != "gpt-5.6-luna" || cfg.WakeupReasoningEffort != "low" {
		t.Fatalf("unexpected defaults: %#v", cfg)
	}
	if cfg.ScanInterval < MinimumScanInterval {
		t.Fatalf("scan interval = %s", cfg.ScanInterval)
	}
}

func TestParseNestedAndRejectsUnsafeSettings(t *testing.T) {
	cfg, err := Parse([]byte("credential_guard:\n  enabled: true\n  scan_interval: 15m\n  state_dir: ./persist/guard\n  probe_provider: CODEX\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enabled || cfg.ScanInterval != 15*time.Minute || cfg.StateDir != filepath.Clean("./persist/guard") {
		t.Fatalf("parsed config = %#v", cfg)
	}
	if _, err := Parse([]byte("state_dir: \n")); err == nil {
		t.Fatal("empty state_dir must fail closed")
	}
	if _, err := Parse([]byte("scan_interval: 1m\n")); err == nil {
		t.Fatal("sub-minimum scan interval must fail")
	}
	if _, err := Parse([]byte("probe_provider: claude\n")); err == nil {
		t.Fatal("non-Codex probe must fail")
	}
}

func TestWakeupSwitchesAreIndependentAndValidated(t *testing.T) {
	cfg, err := Parse([]byte("initial_wakeup_enabled: true\nreset_wakeup_enabled: false\nwakeup_model: gpt-5.6-luna\nwakeup_reasoning_effort: low\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.InitialWakeupEnabled || cfg.ResetWakeupEnabled {
		t.Fatalf("switches=%#v", cfg)
	}
	if _, err := Parse([]byte("wakeup_model: arbitrary-model\n")); err == nil {
		t.Fatal("arbitrary wakeup model accepted")
	}
	if _, err := Parse([]byte("wakeup_reasoning_effort: extreme\n")); err == nil {
		t.Fatal("arbitrary reasoning effort accepted")
	}
}

func TestValidateStateDirRejectsSymlinkComponents(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := ValidateStateDir(filepath.Join(link, "guard")); err == nil {
		t.Fatal("state_dir symlink component was accepted")
	}
}

func TestValidateStateDirRestrictsPermissions(t *testing.T) {
	dir := filepath.Join("internal", ".test-state-guard")
	defer os.RemoveAll(dir)
	if err := ValidateStateDir(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("state permissions = %o", info.Mode().Perm())
	}
	if err := ValidateStateDir(os.TempDir()); err == nil {
		t.Fatal("temp root must not be accepted")
	}
}
