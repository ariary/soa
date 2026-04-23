package provider

import "context"

// Request represents a completion request to an LLM provider.
type Request struct {
	SystemPrompt string
	UserPrompt   string
	MaxTokens    int
}

// Response represents a completion response from an LLM provider.
type Response struct {
	Content string
	Usage   Usage
}

// Usage contains token usage statistics from a completion.
type Usage struct {
	InputTokens  int
	OutputTokens int
}

// Provider is the interface that all LLM backends must implement.
type Provider interface {
	Name() string
	Complete(ctx context.Context, req Request) (Response, error)
}
