package config

import (
	"os"
	"path/filepath"
	"testing"
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
