package config

import (
	"os"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	CheckURL     string
	Proxy        ProxyConfig
	PollInterval time.Duration
	CheckTimeout time.Duration
	Server       ServerConfig
}

type ProxyConfig struct {
	Port int `yaml:"port"`
}

type ServerConfig struct {
	Port      int         `yaml:"port"`
	CachePath string      `yaml:"cache_path"`
	Rules     RulesConfig `yaml:"rules"`
}

type RulesConfig struct {
	MaxAge      MaxAgeRule      `yaml:"max_age"`
	MinVersions MinVersionsRule `yaml:"min_versions"`
	Analysis    AnalysisRule    `yaml:"analysis"`
}

type MaxAgeRule struct {
	Enabled bool `yaml:"enabled"`
	MinDays int  `yaml:"min_days"`
}

type MinVersionsRule struct {
	Enabled bool `yaml:"enabled"`
	Count   int  `yaml:"count"`
}

type AnalysisRule struct {
	Enabled        bool   `yaml:"enabled"`
	Provider       string `yaml:"provider"`
	APIKeyEnv      string `yaml:"api_key_env"`
	Model          string `yaml:"model"`
	BaseURL        string `yaml:"base_url"`
	MaxSourceBytes int    `yaml:"max_source_bytes"`
	GitHubTokenEnv string `yaml:"github_token_env"`
}

// yamlConfig mirrors Config but uses strings for durations (yaml.v3 compat).
type yamlConfig struct {
	CheckURL     string           `yaml:"check_url"`
	Proxy        ProxyConfig      `yaml:"proxy"`
	PollInterval string           `yaml:"poll_interval"`
	CheckTimeout string           `yaml:"check_timeout"`
	Server       yamlServerConfig `yaml:"server"`
}

type yamlServerConfig struct {
	Port      int             `yaml:"port"`
	CachePath string          `yaml:"cache_path"`
	Rules     yamlRulesConfig `yaml:"rules"`
}

type yamlRulesConfig struct {
	MaxAge      yamlMaxAgeRule      `yaml:"max_age"`
	MinVersions yamlMinVersionsRule `yaml:"min_versions"`
	Analysis    yamlAnalysisRule    `yaml:"analysis"`
}

type yamlMaxAgeRule struct {
	Enabled *bool `yaml:"enabled"`
	MinDays int   `yaml:"min_days"`
}

type yamlMinVersionsRule struct {
	Enabled *bool `yaml:"enabled"`
	Count   int   `yaml:"count"`
}

type yamlAnalysisRule struct {
	Enabled        *bool  `yaml:"enabled"`
	Provider       string `yaml:"provider"`
	APIKeyEnv      string `yaml:"api_key_env"`
	Model          string `yaml:"model"`
	BaseURL        string `yaml:"base_url"`
	MaxSourceBytes int    `yaml:"max_source_bytes"`
	GitHubTokenEnv string `yaml:"github_token_env"`
}

func defaults() Config {
	return Config{
		CheckURL:     "http://localhost:9090",
		Proxy:        ProxyConfig{Port: 8080},
		PollInterval: 500 * time.Millisecond,
		CheckTimeout: 30 * time.Second,
		Server: ServerConfig{
			Port:      9090,
			CachePath: "~/.config/soa/approved.json",
			Rules: RulesConfig{
				MaxAge: MaxAgeRule{
					Enabled: true,
					MinDays: 7,
				},
				MinVersions: MinVersionsRule{
					Enabled: true,
					Count:   2,
				},
				Analysis: AnalysisRule{
					Enabled:        false,
					Provider:       "ollama",
					Model:          "llama3",
					MaxSourceBytes: 524288,
				},
			},
		},
	}
}

func Load() Config {
	home, _ := os.UserHomeDir()
	path := home + "/.config/soa/config.yaml"
	return LoadWithPath(path)
}

func LoadWithPath(path string) Config {
	cfg := defaults()
	if path != "" {
		if data, err := os.ReadFile(path); err == nil {
			var yc yamlConfig
			if yaml.Unmarshal(data, &yc) == nil {
				if yc.CheckURL != "" {
					cfg.CheckURL = yc.CheckURL
				}
				if yc.Proxy.Port != 0 {
					cfg.Proxy.Port = yc.Proxy.Port
				}
				if yc.PollInterval != "" {
					if d, err := time.ParseDuration(yc.PollInterval); err == nil {
						cfg.PollInterval = d
					}
				}
				if yc.CheckTimeout != "" {
					if d, err := time.ParseDuration(yc.CheckTimeout); err == nil {
						cfg.CheckTimeout = d
					}
				}
				if yc.Server.Port != 0 {
					cfg.Server.Port = yc.Server.Port
				}
				if yc.Server.CachePath != "" {
					cfg.Server.CachePath = yc.Server.CachePath
				}
				// Rules: max_age
				if yc.Server.Rules.MaxAge.Enabled != nil {
					cfg.Server.Rules.MaxAge.Enabled = *yc.Server.Rules.MaxAge.Enabled
				}
				if yc.Server.Rules.MaxAge.MinDays != 0 {
					cfg.Server.Rules.MaxAge.MinDays = yc.Server.Rules.MaxAge.MinDays
				}
				// Rules: min_versions
				if yc.Server.Rules.MinVersions.Enabled != nil {
					cfg.Server.Rules.MinVersions.Enabled = *yc.Server.Rules.MinVersions.Enabled
				}
				if yc.Server.Rules.MinVersions.Count != 0 {
					cfg.Server.Rules.MinVersions.Count = yc.Server.Rules.MinVersions.Count
				}
				// Rules: analysis
				if yc.Server.Rules.Analysis.Enabled != nil {
					cfg.Server.Rules.Analysis.Enabled = *yc.Server.Rules.Analysis.Enabled
				}
				if yc.Server.Rules.Analysis.Provider != "" {
					cfg.Server.Rules.Analysis.Provider = yc.Server.Rules.Analysis.Provider
				}
				if yc.Server.Rules.Analysis.APIKeyEnv != "" {
					cfg.Server.Rules.Analysis.APIKeyEnv = yc.Server.Rules.Analysis.APIKeyEnv
				}
				if yc.Server.Rules.Analysis.Model != "" {
					cfg.Server.Rules.Analysis.Model = yc.Server.Rules.Analysis.Model
				}
				if yc.Server.Rules.Analysis.BaseURL != "" {
					cfg.Server.Rules.Analysis.BaseURL = yc.Server.Rules.Analysis.BaseURL
				}
				if yc.Server.Rules.Analysis.MaxSourceBytes != 0 {
					cfg.Server.Rules.Analysis.MaxSourceBytes = yc.Server.Rules.Analysis.MaxSourceBytes
				}
				if yc.Server.Rules.Analysis.GitHubTokenEnv != "" {
					cfg.Server.Rules.Analysis.GitHubTokenEnv = yc.Server.Rules.Analysis.GitHubTokenEnv
				}
			}
		}
	}
	applyEnv(&cfg)
	return cfg
}

func parseBoolEnv(v string) (bool, bool) {
	if v == "true" || v == "1" {
		return true, true
	}
	if v == "false" || v == "0" {
		return false, true
	}
	return false, false
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("SOA_CHECK_URL"); v != "" {
		cfg.CheckURL = v
	}
	if v := os.Getenv("SOA_PROXY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Proxy.Port = p
		}
	}
	if v := os.Getenv("SOA_CHECK_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.CheckTimeout = d
		}
	}
	if v := os.Getenv("SOA_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.PollInterval = d
		}
	}
	if v := os.Getenv("SOA_SERVER_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
		}
	}
	if v := os.Getenv("SOA_SERVER_CACHE_PATH"); v != "" {
		cfg.Server.CachePath = v
	}
	// Rules: max_age
	if v := os.Getenv("SOA_RULE_MAX_AGE_ENABLED"); v != "" {
		if b, ok := parseBoolEnv(v); ok {
			cfg.Server.Rules.MaxAge.Enabled = b
		}
	}
	if v := os.Getenv("SOA_RULE_MAX_AGE_MIN_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil {
			cfg.Server.Rules.MaxAge.MinDays = d
		}
	}
	// Rules: min_versions
	if v := os.Getenv("SOA_RULE_MIN_VERSIONS_ENABLED"); v != "" {
		if b, ok := parseBoolEnv(v); ok {
			cfg.Server.Rules.MinVersions.Enabled = b
		}
	}
	if v := os.Getenv("SOA_RULE_MIN_VERSIONS_COUNT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Rules.MinVersions.Count = n
		}
	}
	// Rules: analysis
	if v := os.Getenv("SOA_RULE_ANALYSIS_ENABLED"); v != "" {
		if b, ok := parseBoolEnv(v); ok {
			cfg.Server.Rules.Analysis.Enabled = b
		}
	}
	if v := os.Getenv("SOA_ANALYSIS_PROVIDER"); v != "" {
		cfg.Server.Rules.Analysis.Provider = v
	}
	if v := os.Getenv("SOA_ANALYSIS_API_KEY_ENV"); v != "" {
		cfg.Server.Rules.Analysis.APIKeyEnv = v
	}
	if v := os.Getenv("SOA_ANALYSIS_MODEL"); v != "" {
		cfg.Server.Rules.Analysis.Model = v
	}
	if v := os.Getenv("SOA_ANALYSIS_BASE_URL"); v != "" {
		cfg.Server.Rules.Analysis.BaseURL = v
	}
	if v := os.Getenv("SOA_ANALYSIS_MAX_SOURCE_BYTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Rules.Analysis.MaxSourceBytes = n
		}
	}
	if v := os.Getenv("SOA_ANALYSIS_GITHUB_TOKEN_ENV"); v != "" {
		cfg.Server.Rules.Analysis.GitHubTokenEnv = v
	}
}
