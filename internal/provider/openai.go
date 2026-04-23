package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// OpenAI implements the Provider interface using the OpenAI chat completions API.
type OpenAI struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

// NewOpenAI creates a new OpenAI provider. If baseURL is empty, it defaults
// to https://api.openai.com/v1.
func NewOpenAI(baseURL, apiKey, model string) *OpenAI {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	return &OpenAI{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{},
	}
}

// Name returns "openai".
func (o *OpenAI) Name() string {
	return "openai"
}

type openaiMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openaiResponseFormat struct {
	Type string `json:"type"`
}

type openaiChatRequest struct {
	Model          string               `json:"model"`
	Messages       []openaiMessage      `json:"messages"`
	ResponseFormat openaiResponseFormat `json:"response_format"`
	MaxTokens      int                  `json:"max_tokens,omitempty"`
}

type openaiChatResponse struct {
	Choices []struct {
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Complete sends a chat completion request to the OpenAI API.
func (o *OpenAI) Complete(ctx context.Context, req Request) (Response, error) {
	chatReq := openaiChatRequest{
		Model: o.model,
		Messages: []openaiMessage{
			{Role: "system", Content: req.SystemPrompt},
			{Role: "user", Content: req.UserPrompt},
		},
		ResponseFormat: openaiResponseFormat{Type: "json_object"},
	}

	if req.MaxTokens > 0 {
		chatReq.MaxTokens = req.MaxTokens
	}

	body, err := json.Marshal(chatReq)
	if err != nil {
		return Response{}, fmt.Errorf("openai: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("openai: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)

	httpResp, err := o.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("openai: send request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		return Response{}, fmt.Errorf("openai: unexpected status %d: %s", httpResp.StatusCode, string(respBody))
	}

	var chatResp openaiChatResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&chatResp); err != nil {
		return Response{}, fmt.Errorf("openai: decode response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return Response{}, fmt.Errorf("openai: no choices in response")
	}

	return Response{
		Content: chatResp.Choices[0].Message.Content,
		Usage: Usage{
			InputTokens:  chatResp.Usage.PromptTokens,
			OutputTokens: chatResp.Usage.CompletionTokens,
		},
	}, nil
}
