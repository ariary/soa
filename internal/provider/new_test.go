package provider

import (
	"testing"

	"github.com/ariary/soa/internal/config"
)

func TestNewOllamaProvider(t *testing.T) {
	cfg := config.AnalysisRule{
		Provider: "ollama",
		Model:    "llama3",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if p.Name() != "ollama" {
		t.Errorf("expected Name() = %q, got %q", "ollama", p.Name())
	}
}

func TestNewOllamaProviderDefaultBaseURL(t *testing.T) {
	cfg := config.AnalysisRule{
		Provider: "ollama",
		Model:    "llama3",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	o, ok := p.(*Ollama)
	if !ok {
		t.Fatalf("expected *Ollama, got %T", p)
	}
	if o.baseURL != "http://localhost:11434" {
		t.Errorf("expected default baseURL %q, got %q", "http://localhost:11434", o.baseURL)
	}
}

func TestNewOpenAIProvider(t *testing.T) {
	t.Setenv("TEST_OPENAI_KEY", "sk-test-123")

	cfg := config.AnalysisRule{
		Provider:  "openai",
		Model:     "gpt-4o",
		APIKeyEnv: "TEST_OPENAI_KEY",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if p.Name() != "openai" {
		t.Errorf("expected Name() = %q, got %q", "openai", p.Name())
	}
}

func TestNewOpenAIProviderMissingKey(t *testing.T) {
	cfg := config.AnalysisRule{
		Provider:  "openai",
		Model:     "gpt-4o",
		APIKeyEnv: "TEST_OPENAI_KEY_MISSING",
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for missing API key, got nil")
	}
}

func TestNewGeminiProvider(t *testing.T) {
	t.Setenv("TEST_GEMINI_KEY", "gemini-test-123")

	cfg := config.AnalysisRule{
		Provider:  "gemini",
		Model:     "gemini-pro",
		APIKeyEnv: "TEST_GEMINI_KEY",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	if p.Name() != "gemini" {
		t.Errorf("expected Name() = %q, got %q", "gemini", p.Name())
	}
}

func TestNewGeminiProviderMissingKey(t *testing.T) {
	cfg := config.AnalysisRule{
		Provider:  "gemini",
		Model:     "gemini-pro",
		APIKeyEnv: "TEST_GEMINI_KEY_MISSING",
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for missing API key, got nil")
	}
}

func TestNewUnknownProvider(t *testing.T) {
	cfg := config.AnalysisRule{
		Provider: "unknown",
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("expected error for unknown provider, got nil")
	}
}

func TestNewOllamaProvider_CustomBaseURL(t *testing.T) {
	cfg := config.AnalysisRule{
		Provider: "ollama",
		Model:    "llama3",
		BaseURL:  "http://remote-host:11434",
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}
	o, ok := p.(*Ollama)
	if !ok {
		t.Fatalf("expected *Ollama, got %T", p)
	}
	if o.baseURL != "http://remote-host:11434" {
		t.Errorf("expected custom baseURL %q, got %q", "http://remote-host:11434", o.baseURL)
	}
}
