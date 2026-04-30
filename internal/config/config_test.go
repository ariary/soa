package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg := LoadWithPath("")
	if cfg.CheckURL != "http://localhost:9090" {
		t.Errorf("expected default check_url, got %s", cfg.CheckURL)
	}
	if cfg.Proxy.Port != 8080 {
		t.Errorf("expected default proxy port 8080, got %d", cfg.Proxy.Port)
	}
	if cfg.CheckTimeout.String() != "30s" {
		t.Errorf("expected default check_timeout 30s, got %s", cfg.CheckTimeout)
	}
	if cfg.PollInterval.String() != "500ms" {
		t.Errorf("expected default poll_interval 500ms, got %s", cfg.PollInterval)
	}
	if cfg.Server.Rules.MaxAge.MinDays != 7 {
		t.Errorf("expected default max_age min_days 7, got %d", cfg.Server.Rules.MaxAge.MinDays)
	}
}

func TestLoadDefaults_Rules(t *testing.T) {
	cfg := LoadWithPath("")

	// max_age defaults
	if !cfg.Server.Rules.MaxAge.Enabled {
		t.Error("expected max_age enabled=true by default")
	}
	if cfg.Server.Rules.MaxAge.MinDays != 7 {
		t.Errorf("expected max_age min_days=7, got %d", cfg.Server.Rules.MaxAge.MinDays)
	}

	// analysis defaults
	if cfg.Server.Rules.Analysis.Enabled {
		t.Error("expected analysis enabled=false by default")
	}
	if cfg.Server.Rules.Analysis.Provider != "ollama" {
		t.Errorf("expected analysis provider=ollama, got %s", cfg.Server.Rules.Analysis.Provider)
	}
	if cfg.Server.Rules.Analysis.Model != "llama3" {
		t.Errorf("expected analysis model=llama3, got %s", cfg.Server.Rules.Analysis.Model)
	}
	if cfg.Server.Rules.Analysis.MaxSourceBytes != 524288 {
		t.Errorf("expected analysis max_source_bytes=524288, got %d", cfg.Server.Rules.Analysis.MaxSourceBytes)
	}
	if cfg.Server.Rules.Analysis.APIKeyEnv != "" {
		t.Errorf("expected analysis api_key_env empty, got %s", cfg.Server.Rules.Analysis.APIKeyEnv)
	}
	if cfg.Server.Rules.Analysis.BaseURL != "" {
		t.Errorf("expected analysis base_url empty, got %s", cfg.Server.Rules.Analysis.BaseURL)
	}
	if cfg.Server.Rules.Analysis.GitHubTokenEnv != "" {
		t.Errorf("expected analysis github_token_env empty, got %s", cfg.Server.Rules.Analysis.GitHubTokenEnv)
	}
}

func TestLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("check_url: http://firewall:443\nproxy:\n  port: 9999\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadWithPath(path)
	if cfg.CheckURL != "http://firewall:443" {
		t.Errorf("expected check_url from file, got %s", cfg.CheckURL)
	}
	if cfg.Proxy.Port != 9999 {
		t.Errorf("expected proxy port 9999, got %d", cfg.Proxy.Port)
	}
}

func TestLoadFromFile_Rules(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`server:
  port: 9090
  rules:
    max_age:
      enabled: false
      min_days: 30
    analysis:
      enabled: true
      provider: openai
      api_key_env: OPENAI_API_KEY
      model: gpt-4
      base_url: https://api.openai.com/v1
      max_source_bytes: 1048576
      github_token_env: GITHUB_TOKEN
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadWithPath(path)

	// max_age
	if cfg.Server.Rules.MaxAge.Enabled {
		t.Error("expected max_age enabled=false from file")
	}
	if cfg.Server.Rules.MaxAge.MinDays != 30 {
		t.Errorf("expected max_age min_days=30, got %d", cfg.Server.Rules.MaxAge.MinDays)
	}

	// analysis
	if !cfg.Server.Rules.Analysis.Enabled {
		t.Error("expected analysis enabled=true from file")
	}
	if cfg.Server.Rules.Analysis.Provider != "openai" {
		t.Errorf("expected provider=openai, got %s", cfg.Server.Rules.Analysis.Provider)
	}
	if cfg.Server.Rules.Analysis.APIKeyEnv != "OPENAI_API_KEY" {
		t.Errorf("expected api_key_env=OPENAI_API_KEY, got %s", cfg.Server.Rules.Analysis.APIKeyEnv)
	}
	if cfg.Server.Rules.Analysis.Model != "gpt-4" {
		t.Errorf("expected model=gpt-4, got %s", cfg.Server.Rules.Analysis.Model)
	}
	if cfg.Server.Rules.Analysis.BaseURL != "https://api.openai.com/v1" {
		t.Errorf("expected base_url=https://api.openai.com/v1, got %s", cfg.Server.Rules.Analysis.BaseURL)
	}
	if cfg.Server.Rules.Analysis.MaxSourceBytes != 1048576 {
		t.Errorf("expected max_source_bytes=1048576, got %d", cfg.Server.Rules.Analysis.MaxSourceBytes)
	}
	if cfg.Server.Rules.Analysis.GitHubTokenEnv != "GITHUB_TOKEN" {
		t.Errorf("expected github_token_env=GITHUB_TOKEN, got %s", cfg.Server.Rules.Analysis.GitHubTokenEnv)
	}
}

func TestEnvVarOverrides(t *testing.T) {
	t.Setenv("SOA_CHECK_URL", "http://env-override:1234")
	t.Setenv("SOA_PROXY_PORT", "7777")
	cfg := LoadWithPath("")
	if cfg.CheckURL != "http://env-override:1234" {
		t.Errorf("expected env override, got %s", cfg.CheckURL)
	}
	if cfg.Proxy.Port != 7777 {
		t.Errorf("expected env port 7777, got %d", cfg.Proxy.Port)
	}
}

func TestEnvVarOverrides_Rules(t *testing.T) {
	// max_age env overrides
	t.Setenv("SOA_RULE_MAX_AGE_ENABLED", "false")
	t.Setenv("SOA_RULE_MAX_AGE_MIN_DAYS", "14")
	// analysis env overrides
	t.Setenv("SOA_RULE_ANALYSIS_ENABLED", "1")
	t.Setenv("SOA_ANALYSIS_PROVIDER", "openai")
	t.Setenv("SOA_ANALYSIS_API_KEY_ENV", "MY_KEY")
	t.Setenv("SOA_ANALYSIS_MODEL", "gpt-4o")
	t.Setenv("SOA_ANALYSIS_BASE_URL", "https://custom.api/v1")
	t.Setenv("SOA_ANALYSIS_MAX_SOURCE_BYTES", "2097152")
	t.Setenv("SOA_ANALYSIS_GITHUB_TOKEN_ENV", "GH_TOKEN")

	cfg := LoadWithPath("")

	// max_age
	if cfg.Server.Rules.MaxAge.Enabled {
		t.Error("expected max_age enabled=false from env")
	}
	if cfg.Server.Rules.MaxAge.MinDays != 14 {
		t.Errorf("expected max_age min_days=14, got %d", cfg.Server.Rules.MaxAge.MinDays)
	}

	// analysis
	if !cfg.Server.Rules.Analysis.Enabled {
		t.Error("expected analysis enabled=true from env (SOA_RULE_ANALYSIS_ENABLED=1)")
	}
	if cfg.Server.Rules.Analysis.Provider != "openai" {
		t.Errorf("expected provider=openai, got %s", cfg.Server.Rules.Analysis.Provider)
	}
	if cfg.Server.Rules.Analysis.APIKeyEnv != "MY_KEY" {
		t.Errorf("expected api_key_env=MY_KEY, got %s", cfg.Server.Rules.Analysis.APIKeyEnv)
	}
	if cfg.Server.Rules.Analysis.Model != "gpt-4o" {
		t.Errorf("expected model=gpt-4o, got %s", cfg.Server.Rules.Analysis.Model)
	}
	if cfg.Server.Rules.Analysis.BaseURL != "https://custom.api/v1" {
		t.Errorf("expected base_url=https://custom.api/v1, got %s", cfg.Server.Rules.Analysis.BaseURL)
	}
	if cfg.Server.Rules.Analysis.MaxSourceBytes != 2097152 {
		t.Errorf("expected max_source_bytes=2097152, got %d", cfg.Server.Rules.Analysis.MaxSourceBytes)
	}
	if cfg.Server.Rules.Analysis.GitHubTokenEnv != "GH_TOKEN" {
		t.Errorf("expected github_token_env=GH_TOKEN, got %s", cfg.Server.Rules.Analysis.GitHubTokenEnv)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte("check_url: http://from-file:80\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOA_CHECK_URL", "http://from-env:443")
	cfg := LoadWithPath(path)
	if cfg.CheckURL != "http://from-env:443" {
		t.Errorf("expected env to override file, got %s", cfg.CheckURL)
	}
}

// --- Tests to kill CONDITIONALS_NEGATION mutants ---

// YAML overrides for PollInterval, CheckTimeout, Server.Port, Server.CachePath, MinVersions.Count
func TestLoadFromFile_DurationAndServerFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`poll_interval: "2s"
check_timeout: "10s"
server:
  port: 7070
  cache_path: "/tmp/custom-cache.json"
  rules:
    min_versions:
      count: 5
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadWithPath(path)

	// Line 143: yc.PollInterval != ""
	if cfg.PollInterval != 2*time.Second {
		t.Errorf("expected poll_interval 2s from YAML, got %s", cfg.PollInterval)
	}
	// Line 148: yc.CheckTimeout != ""
	if cfg.CheckTimeout != 10*time.Second {
		t.Errorf("expected check_timeout 10s from YAML, got %s", cfg.CheckTimeout)
	}
	// Line 153: yc.Server.Port != 0
	if cfg.Server.Port != 7070 {
		t.Errorf("expected server port 7070 from YAML, got %d", cfg.Server.Port)
	}
	// Line 156: yc.Server.CachePath != ""
	if cfg.Server.CachePath != "/tmp/custom-cache.json" {
		t.Errorf("expected cache_path /tmp/custom-cache.json from YAML, got %s", cfg.Server.CachePath)
	}
	// Line 170: yc.Server.Rules.MinVersions.Count != 0
	if cfg.Server.Rules.MinVersions.Count != 5 {
		t.Errorf("expected min_versions count 5 from YAML, got %d", cfg.Server.Rules.MinVersions.Count)
	}
}

// Ensure defaults are preserved when YAML fields are absent (zero-value).
// A CONDITIONALS_NEGATION mutant would override defaults with zero values.
func TestLoadFromFile_OmittedFieldsKeepDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// YAML file with only check_url; all other fields are absent/zero.
	data := []byte("check_url: http://minimal:80\n")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadWithPath(path)

	if cfg.PollInterval != 500*time.Millisecond {
		t.Errorf("expected default poll_interval 500ms when omitted in YAML, got %s", cfg.PollInterval)
	}
	if cfg.CheckTimeout != 30*time.Second {
		t.Errorf("expected default check_timeout 30s when omitted in YAML, got %s", cfg.CheckTimeout)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("expected default server port 9090 when omitted in YAML, got %d", cfg.Server.Port)
	}
	if cfg.Server.CachePath != "~/.config/soa/approved.json" {
		t.Errorf("expected default cache_path when omitted in YAML, got %s", cfg.Server.CachePath)
	}
	if cfg.Server.Rules.MinVersions.Count != 2 {
		t.Errorf("expected default min_versions count 2 when omitted in YAML, got %d", cfg.Server.Rules.MinVersions.Count)
	}
}

// Env var overrides for SOA_CHECK_TIMEOUT, SOA_POLL_INTERVAL, SOA_SERVER_PORT,
// SOA_SERVER_CACHE_PATH, SOA_RULE_MIN_VERSIONS_ENABLED, SOA_RULE_MIN_VERSIONS_COUNT
func TestEnvVarOverrides_ServerAndDurations(t *testing.T) {
	t.Setenv("SOA_CHECK_TIMEOUT", "5s")
	t.Setenv("SOA_POLL_INTERVAL", "1s")
	t.Setenv("SOA_SERVER_PORT", "4444")
	t.Setenv("SOA_SERVER_CACHE_PATH", "/tmp/env-cache.json")
	t.Setenv("SOA_RULE_MIN_VERSIONS_ENABLED", "false")
	t.Setenv("SOA_RULE_MIN_VERSIONS_COUNT", "10")

	cfg := LoadWithPath("")

	// Line 221: SOA_CHECK_TIMEOUT
	if cfg.CheckTimeout != 5*time.Second {
		t.Errorf("expected check_timeout 5s from env, got %s", cfg.CheckTimeout)
	}
	// Line 226: SOA_POLL_INTERVAL
	if cfg.PollInterval != 1*time.Second {
		t.Errorf("expected poll_interval 1s from env, got %s", cfg.PollInterval)
	}
	// Line 231: SOA_SERVER_PORT
	if cfg.Server.Port != 4444 {
		t.Errorf("expected server port 4444 from env, got %d", cfg.Server.Port)
	}
	// Line 236: SOA_SERVER_CACHE_PATH
	if cfg.Server.CachePath != "/tmp/env-cache.json" {
		t.Errorf("expected cache_path /tmp/env-cache.json from env, got %s", cfg.Server.CachePath)
	}
	// Line 251: SOA_RULE_MIN_VERSIONS_ENABLED
	if cfg.Server.Rules.MinVersions.Enabled {
		t.Error("expected min_versions enabled=false from env")
	}
	// Line 256: SOA_RULE_MIN_VERSIONS_COUNT
	if cfg.Server.Rules.MinVersions.Count != 10 {
		t.Errorf("expected min_versions count 10 from env, got %d", cfg.Server.Rules.MinVersions.Count)
	}
}

// Ensure defaults remain when env vars are NOT set (kills CONDITIONALS_NEGATION mutants
// that would apply the override branch when the env var is empty).
func TestEnvVarOverrides_UnsetKeepsDefaults(t *testing.T) {
	// Explicitly ensure these env vars are unset (t.Setenv not called).
	cfg := LoadWithPath("")

	if cfg.CheckTimeout != 30*time.Second {
		t.Errorf("expected default check_timeout 30s when env unset, got %s", cfg.CheckTimeout)
	}
	if cfg.PollInterval != 500*time.Millisecond {
		t.Errorf("expected default poll_interval 500ms when env unset, got %s", cfg.PollInterval)
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("expected default server port 9090 when env unset, got %d", cfg.Server.Port)
	}
	if cfg.Server.CachePath != "~/.config/soa/approved.json" {
		t.Errorf("expected default cache_path when env unset, got %s", cfg.Server.CachePath)
	}
	if !cfg.Server.Rules.MinVersions.Enabled {
		t.Error("expected default min_versions enabled=true when env unset")
	}
	if cfg.Server.Rules.MinVersions.Count != 2 {
		t.Errorf("expected default min_versions count 2 when env unset, got %d", cfg.Server.Rules.MinVersions.Count)
	}
}

// parseBoolEnv: test "false" and "0" return (false, true)
// Line 206: v == "false" || v == "0"
func TestParseBoolEnv_FalseAndZero(t *testing.T) {
	tests := []struct {
		input    string
		wantVal  bool
		wantOk   bool
	}{
		{"false", false, true},
		{"0", false, true},
		{"true", true, true},
		{"1", true, true},
		{"invalid", false, false},
		{"", false, false},
		{"yes", false, false},
	}
	for _, tt := range tests {
		val, ok := parseBoolEnv(tt.input)
		if val != tt.wantVal || ok != tt.wantOk {
			t.Errorf("parseBoolEnv(%q) = (%v, %v), want (%v, %v)",
				tt.input, val, ok, tt.wantVal, tt.wantOk)
		}
	}
}

// Integration: SOA_RULE_MIN_VERSIONS_ENABLED with "0" (exercises parseBoolEnv "0" path
// through the full applyEnv flow).
func TestEnvVarOverrides_MinVersionsEnabledWithZero(t *testing.T) {
	t.Setenv("SOA_RULE_MIN_VERSIONS_ENABLED", "0")
	cfg := LoadWithPath("")
	if cfg.Server.Rules.MinVersions.Enabled {
		t.Error("expected min_versions enabled=false when SOA_RULE_MIN_VERSIONS_ENABLED=0")
	}
}

// Integration: env vars override YAML values (not just defaults).
func TestEnvOverridesYAML_ServerAndDurations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	data := []byte(`poll_interval: "2s"
check_timeout: "10s"
server:
  port: 7070
  cache_path: "/tmp/yaml-cache.json"
  rules:
    min_versions:
      count: 5
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	t.Setenv("SOA_POLL_INTERVAL", "3s")
	t.Setenv("SOA_CHECK_TIMEOUT", "15s")
	t.Setenv("SOA_SERVER_PORT", "8888")
	t.Setenv("SOA_SERVER_CACHE_PATH", "/tmp/env-wins.json")
	t.Setenv("SOA_RULE_MIN_VERSIONS_COUNT", "99")

	cfg := LoadWithPath(path)

	if cfg.PollInterval != 3*time.Second {
		t.Errorf("expected env poll_interval 3s to override YAML, got %s", cfg.PollInterval)
	}
	if cfg.CheckTimeout != 15*time.Second {
		t.Errorf("expected env check_timeout 15s to override YAML, got %s", cfg.CheckTimeout)
	}
	if cfg.Server.Port != 8888 {
		t.Errorf("expected env server port 8888 to override YAML, got %d", cfg.Server.Port)
	}
	if cfg.Server.CachePath != "/tmp/env-wins.json" {
		t.Errorf("expected env cache_path to override YAML, got %s", cfg.Server.CachePath)
	}
	if cfg.Server.Rules.MinVersions.Count != 99 {
		t.Errorf("expected env min_versions count 99 to override YAML, got %d", cfg.Server.Rules.MinVersions.Count)
	}
}
