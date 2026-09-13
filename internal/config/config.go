// Package config owns Credential Guard configuration parsing and conservative
// validation. No other package applies defaults or interprets duration strings.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultStateDir       = "plugins/cpa-credential-guard-data"
	DefaultScanInterval   = 10 * time.Minute
	DefaultInitialBackoff = 15 * time.Minute
	DefaultMaxBackoff     = 24 * time.Hour
	DefaultProbeTimeout   = 10 * time.Second
	MinimumScanInterval   = 10 * time.Minute
)

// Config is the normalized plugin configuration. It is deliberately flat:
// CPA supplies a plugin's config_yaml without the surrounding CPA config.
type Config struct {
	Enabled                  bool
	StateDir                 string
	RecoveryEnabled          bool
	ScanInterval             time.Duration
	InitialBackoff           time.Duration
	MaxBackoff               time.Duration
	ProbeEnabled             bool
	ProbeProvider            string
	ProbeModel               string
	ProbeTimeout             time.Duration
	QuotaDetectionEnabled    bool
	DetectHTTP429            bool
	ClassifyGenericRateLimit bool
	ProxyManagementEnabled   bool
}

// Inert returns true when automatic writes and recovery must not run.
func (c Config) Inert() bool { return !c.Enabled }

// EffectiveProjection avoids exposing the configured filesystem path or the
// informational model value to an unauthenticated response.
func (c Config) EffectiveProjection() map[string]any {
	return map[string]any{
		"enabled":                     c.Enabled,
		"state_dir_configured":        strings.TrimSpace(c.StateDir) != "",
		"recovery_enabled":            c.RecoveryEnabled,
		"scan_interval":               c.ScanInterval.String(),
		"initial_backoff":             c.InitialBackoff.String(),
		"max_backoff":                 c.MaxBackoff.String(),
		"probe_enabled":               c.ProbeEnabled,
		"probe_provider":              c.ProbeProvider,
		"probe_model_configured":      strings.TrimSpace(c.ProbeModel) != "",
		"probe_timeout":               c.ProbeTimeout.String(),
		"quota_detection_enabled":     c.QuotaDetectionEnabled,
		"detect_http_429":             c.DetectHTTP429,
		"classify_generic_rate_limit": c.ClassifyGenericRateLimit,
		"proxy_management_enabled":    c.ProxyManagementEnabled,
	}
}

// Parse parses the normalized plugin YAML. An empty/missing configuration is
// valid but disabled. If a deployment explicitly supplies an empty state_dir,
// parsing fails instead of choosing a temporary or process-local fallback.
func Parse(raw []byte) (Config, error) {
	cfg := defaults()
	if len(strings.TrimSpace(string(raw))) == 0 {
		return cfg, nil
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return Config{}, fmt.Errorf("decode plugin configuration: %w", err)
	}
	mapping := rootMap(&root)
	if len(mapping) == 0 && rootMapNodeKind(&root) != yaml.MappingNode {
		return Config{}, errors.New("plugin configuration must be a mapping")
	}
	if nested, ok := mapping["credential_guard"]; ok {
		if nested == nil || nested.Kind != yaml.MappingNode {
			return Config{}, errors.New("credential_guard must be a mapping")
		}
		mapping = nodeMap(nested)
	}
	if err := applyBool(mapping, "enabled", &cfg.Enabled); err != nil {
		return Config{}, err
	}
	if value, present := mapping["state_dir"]; present {
		v, err := scalarString(value, "state_dir")
		if err != nil {
			return Config{}, err
		}
		if strings.TrimSpace(v) == "" {
			return Config{}, errors.New("state_dir must not be empty")
		}
		cfg.StateDir = filepath.Clean(v)
	}
	if err := applyBool(mapping, "recovery_enabled", &cfg.RecoveryEnabled); err != nil {
		return Config{}, err
	}
	if err := applyDuration(mapping, "scan_interval", &cfg.ScanInterval); err != nil {
		return Config{}, err
	}
	if err := applyDuration(mapping, "initial_backoff", &cfg.InitialBackoff); err != nil {
		return Config{}, err
	}
	if err := applyDuration(mapping, "max_backoff", &cfg.MaxBackoff); err != nil {
		return Config{}, err
	}
	if err := applyBool(mapping, "probe_enabled", &cfg.ProbeEnabled); err != nil {
		return Config{}, err
	}
	if value, present := mapping["probe_provider"]; present {
		v, err := scalarString(value, "probe_provider")
		if err != nil {
			return Config{}, err
		}
		cfg.ProbeProvider = strings.ToLower(strings.TrimSpace(v))
	}
	if value, present := mapping["probe_model"]; present {
		v, err := scalarString(value, "probe_model")
		if err != nil {
			return Config{}, err
		}
		cfg.ProbeModel = strings.TrimSpace(v)
	}
	if err := applyDuration(mapping, "probe_timeout", &cfg.ProbeTimeout); err != nil {
		return Config{}, err
	}
	if err := applyBool(mapping, "quota_detection_enabled", &cfg.QuotaDetectionEnabled); err != nil {
		return Config{}, err
	}
	if err := applyBool(mapping, "detect_http_429", &cfg.DetectHTTP429); err != nil {
		return Config{}, err
	}
	if err := applyBool(mapping, "classify_generic_rate_limit", &cfg.ClassifyGenericRateLimit); err != nil {
		return Config{}, err
	}
	if err := applyBool(mapping, "proxy_management_enabled", &cfg.ProxyManagementEnabled); err != nil {
		return Config{}, err
	}
	if err := Validate(&cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func defaults() Config {
	return Config{
		Enabled:                  false,
		StateDir:                 DefaultStateDir,
		RecoveryEnabled:          true,
		ScanInterval:             DefaultScanInterval,
		InitialBackoff:           DefaultInitialBackoff,
		MaxBackoff:               DefaultMaxBackoff,
		ProbeEnabled:             true,
		ProbeProvider:            "codex",
		ProbeTimeout:             DefaultProbeTimeout,
		QuotaDetectionEnabled:    true,
		DetectHTTP429:            true,
		ClassifyGenericRateLimit: false,
		ProxyManagementEnabled:   true,
	}
}

// Validate rejects unsafe state paths and configurations that could create a
// high-frequency recovery loop. It does not create directories.
func Validate(c *Config) error {
	if c == nil {
		return errors.New("configuration is nil")
	}
	if strings.TrimSpace(c.StateDir) == "" {
		return errors.New("state_dir must not be empty")
	}
	if filepath.Clean(c.StateDir) == "." {
		return errors.New("state_dir must identify a directory")
	}
	if strings.ContainsAny(c.StateDir, "\x00\r\n") {
		return errors.New("state_dir contains forbidden characters")
	}
	if c.ScanInterval < MinimumScanInterval {
		return fmt.Errorf("scan_interval must be at least %s", MinimumScanInterval)
	}
	if c.InitialBackoff <= 0 || c.MaxBackoff <= 0 || c.InitialBackoff > c.MaxBackoff {
		return errors.New("backoff must satisfy 0 < initial_backoff <= max_backoff")
	}
	if c.ProbeTimeout <= 0 || c.ProbeTimeout > 10*time.Minute {
		return errors.New("probe_timeout must be between 1ns and 10m")
	}
	if c.ProbeProvider == "" {
		c.ProbeProvider = "codex"
	}
	if c.ProbeProvider != "codex" {
		return fmt.Errorf("probe_provider %q is unavailable; only codex is supported", c.ProbeProvider)
	}
	if isUnsafeStatePath(c.StateDir) {
		return fmt.Errorf("state_dir %q is unsafe", c.StateDir)
	}
	return nil
}

// ValidateStateDir checks the explicit directory contract and creates it with
// restrictive permissions. It never falls back to another location.
func ValidateStateDir(path string) error {
	if strings.TrimSpace(path) == "" || isUnsafeStatePath(path) {
		return errors.New("state_dir is empty or unsafe")
	}
	if err := rejectSymlinkComponents(path); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create state_dir: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect state_dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state_dir is not a regular directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("restrict state_dir: %w", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return fmt.Errorf("verify state_dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("state_dir changed to a non-directory")
	}
	return nil
}

func rejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		if abs, err := filepath.Abs(clean); err == nil {
			clean = abs
		}
	}
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("state_dir must not contain symlink components")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect state_dir: %w", err)
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func isUnsafeStatePath(path string) bool {
	clean := filepath.Clean(path)
	if clean == "." || clean == string(filepath.Separator) {
		return true
	}
	if strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return true
	}
	// Temporary directories and the system temp root are never implicit state
	// locations. Explicit persistent absolute paths remain allowed.
	tmp := filepath.Clean(os.TempDir())
	if clean == tmp || strings.HasPrefix(clean, tmp+string(filepath.Separator)) {
		return true
	}
	return false
}

func rootMapNodeKind(root *yaml.Node) yaml.Kind {
	if root == nil {
		return yaml.Kind(0)
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	return root.Kind
}
func rootMap(root *yaml.Node) map[string]*yaml.Node {
	if root == nil {
		return map[string]*yaml.Node{}
	}
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return map[string]*yaml.Node{}
	}
	return nodeMap(root)
}

func nodeMap(node *yaml.Node) map[string]*yaml.Node {
	out := make(map[string]*yaml.Node)
	if node == nil || node.Kind != yaml.MappingNode {
		return out
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		out[node.Content[i].Value] = node.Content[i+1]
	}
	return out
}

func scalarString(node *yaml.Node, field string) (string, error) {
	if node == nil || node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("%s must be a scalar", field)
	}
	return node.Value, nil
}

func applyBool(m map[string]*yaml.Node, key string, dst *bool) error {
	node, ok := m[key]
	if !ok {
		return nil
	}
	v, err := scalarString(node, key)
	if err != nil {
		return err
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return fmt.Errorf("%s must be boolean: %w", key, err)
	}
	*dst = parsed
	return nil
}

func applyDuration(m map[string]*yaml.Node, key string, dst *time.Duration) error {
	node, ok := m[key]
	if !ok {
		return nil
	}
	v, err := scalarString(node, key)
	if err != nil {
		return err
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("%s must not be empty", key)
	}
	parsed, err := time.ParseDuration(v)
	if err != nil {
		// Accept a YAML integer as nanoseconds only for compatibility with
		// callers that construct config nodes programmatically.
		if n, intErr := strconv.ParseInt(v, 10, 64); intErr == nil {
			parsed = time.Duration(n)
		} else {
			return fmt.Errorf("%s must be a Go duration: %w", key, err)
		}
	}
	*dst = parsed
	return nil
}
