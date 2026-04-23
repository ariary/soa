package provider

import (
	"fmt"
	"os"

	"github.com/ariary/soa/internal/config"
)

// New creates a Provider based on the given AnalysisRule configuration.
func New(cfg config.AnalysisRule) (Provider, error) {
	switch cfg.Provider {
	case "ollama":
		baseURL := cfg.BaseURL
		if baseURL == "" {
			baseURL = "http://localhost:11434"
		}
		return NewOllama(baseURL, cfg.Model), nil

	case "openai":
		apiKey := os.Getenv(cfg.APIKeyEnv)
		if apiKey == "" {
			return nil, fmt.Errorf("provider: environment variable %q is not set", cfg.APIKeyEnv)
		}
		return NewOpenAI(cfg.BaseURL, apiKey, cfg.Model), nil

	case "gemini":
		apiKey := os.Getenv(cfg.APIKeyEnv)
		if apiKey == "" {
			return nil, fmt.Errorf("provider: environment variable %q is not set", cfg.APIKeyEnv)
		}
		return NewGemini(cfg.BaseURL, apiKey, cfg.Model), nil

	default:
		return nil, fmt.Errorf("provider: unknown provider %q", cfg.Provider)
	}
}
