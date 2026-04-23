package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Gemini implements the Provider interface using the Google Gemini API.
type Gemini struct {
	baseURL string
	apiKey  string
	model   string
	client  *http.Client
}

// NewGemini creates a new Gemini provider. If baseURL is empty, it defaults
// to https://generativelanguage.googleapis.com/v1beta.
func NewGemini(baseURL, apiKey, model string) *Gemini {
	if baseURL == "" {
		baseURL = "https://generativelanguage.googleapis.com/v1beta"
	}
	return &Gemini{
		baseURL: baseURL,
		apiKey:  apiKey,
		model:   model,
		client:  &http.Client{},
	}
}

// Name returns "gemini".
func (g *Gemini) Name() string {
	return "gemini"
}

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}

type geminiGenerationConfig struct {
	ResponseMimeType string `json:"responseMimeType"`
	MaxOutputTokens  int    `json:"maxOutputTokens,omitempty"`
}

type geminiRequest struct {
	Contents          []geminiContent        `json:"contents"`
	SystemInstruction geminiContent          `json:"systemInstruction"`
	GenerationConfig  geminiGenerationConfig `json:"generationConfig"`
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text string `json:"text"`
			} `json:"parts"`
		} `json:"content"`
	} `json:"candidates"`
	UsageMetadata struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
}

// Complete sends a generate content request to the Gemini API.
func (g *Gemini) Complete(ctx context.Context, req Request) (Response, error) {
	gemReq := geminiRequest{
		Contents: []geminiContent{
			{
				Parts: []geminiPart{
					{Text: req.UserPrompt},
				},
			},
		},
		SystemInstruction: geminiContent{
			Parts: []geminiPart{
				{Text: req.SystemPrompt},
			},
		},
		GenerationConfig: geminiGenerationConfig{
			ResponseMimeType: "application/json",
		},
	}

	if req.MaxTokens > 0 {
		gemReq.GenerationConfig.MaxOutputTokens = req.MaxTokens
	}

	body, err := json.Marshal(gemReq)
	if err != nil {
		return Response{}, fmt.Errorf("gemini: marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/models/%s:generateContent?key=%s", g.baseURL, g.model, g.apiKey)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return Response{}, fmt.Errorf("gemini: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := g.client.Do(httpReq)
	if err != nil {
		return Response{}, fmt.Errorf("gemini: send request: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(httpResp.Body)
		return Response{}, fmt.Errorf("gemini: unexpected status %d: %s", httpResp.StatusCode, string(respBody))
	}

	var gemResp geminiResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&gemResp); err != nil {
		return Response{}, fmt.Errorf("gemini: decode response: %w", err)
	}

	if len(gemResp.Candidates) == 0 {
		return Response{}, fmt.Errorf("gemini: no candidates in response")
	}

	candidate := gemResp.Candidates[0]
	if len(candidate.Content.Parts) == 0 {
		return Response{}, fmt.Errorf("gemini: no parts in candidate response")
	}

	return Response{
		Content: candidate.Content.Parts[0].Text,
		Usage: Usage{
			InputTokens:  gemResp.UsageMetadata.PromptTokenCount,
			OutputTokens: gemResp.UsageMetadata.CandidatesTokenCount,
		},
	}, nil
}
