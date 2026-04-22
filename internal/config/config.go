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
	Port       int    `yaml:"port"`
	CachePath  string `yaml:"cache_path"`
	MaxAgeDays int    `yaml:"max_age_days"`
}

// yamlConfig mirrors Config but uses strings for durations (yaml.v3 compat).
type yamlConfig struct {
	CheckURL     string       `yaml:"check_url"`
	Proxy        ProxyConfig  `yaml:"proxy"`
	PollInterval string       `yaml:"poll_interval"`
	CheckTimeout string       `yaml:"check_timeout"`
	Server       ServerConfig `yaml:"server"`
}

func defaults() Config {
	return Config{
		CheckURL:     "http://localhost:9090",
		Proxy:        ProxyConfig{Port: 8080},
		PollInterval: 500 * time.Millisecond,
		CheckTimeout: 30 * time.Second,
		Server: ServerConfig{
			Port:       9090,
			CachePath:  "~/.config/soa/approved.json",
			MaxAgeDays: 7,
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
				if yc.Server.MaxAgeDays != 0 {
					cfg.Server.MaxAgeDays = yc.Server.MaxAgeDays
				}
			}
		}
	}
	applyEnv(&cfg)
	return cfg
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
	if v := os.Getenv("SOA_SERVER_MAX_AGE_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil {
			cfg.Server.MaxAgeDays = d
		}
	}
}
