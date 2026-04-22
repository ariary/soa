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
