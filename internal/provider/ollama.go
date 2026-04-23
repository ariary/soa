package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Ollama implements the Provider interface using a local Ollama instance.
type Ollama struct {
	baseURL string
	model   string
	client  *http.Client
}

// NewOllama creates a new Ollama provider. If baseURL is empty, it defaults
// to http://localhost:11434.
func NewOllama(baseURL, model string) *Ollama {
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &Ollama{
		baseURL: baseURL,
		model:   model,
		client:  &http.Client{},
	}
}

// Name returns "ollama".
func (o *Ollama) Name() string {
	return "ollama"
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatRequest struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Format   string              `json:"format"`
	Options  *ollamaOptions      `json:"options,omitempty"`
}

type ollamaOptions struct {
	NumPredict int `json:"num_predict"`
}

type ollamaChatResponse struct {
	Message struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"message"`
	PromptEvalCount int `json:"prompt_eval_count"`
	EvalCount       int `json:"eval_count"`
}

// Complete sends a chat completion request to the Ollama API.
func (o *Ollama) Complete(ctx context.Context, req Request) (Response, error) {
	chatReq := ollamaChatRequest{
		Model: o.model,
		Messages: []ollamaChatMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserPrompt},
		},
		Stream: false,
		Format: "json",
	}

	if req.MaxTokens > 0 {
		chatReq.Options = &ollamaOptions{
			NumPredict: req.MaxTokens,
		}
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return Response{}, fmt.Errorf("ollama: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("ollama: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := o.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("ollama: send request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		return Response{}, fmt.Errorf("ollama: unexpected status %d: %s", httpResp.StatusCode, string(respBody))
	}

	var chatResp ollamaChatResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&chatResp); err != nil {
		return Response{}, fmt.Errorf("ollama: decode response: %w", err)
	}

	return Response{
		Content: chatResp.Message.Content,
		Usage: Usage{
			InputTokens:  chatResp.PromptEvalCount,
			OutputTokens: chatResp.EvalCount,
		},
	}, nil
}
