package provider

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOllamaName(t *testing.T) {
	o := NewOllama("", "llama3")
	if o.Name() != "ollama" {
		t.Errorf("expected Name() = %q, got %q", "ollama", o.Name())
	}
}

func TestOllamaComplete(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method and path
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/chat" {
			t.Errorf("expected /api/chat, got %s", r.URL.Path)
		}

		// Parse and verify request body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		defer r.Body.Close()

		var reqBody map[string]interface{}
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("failed to parse request body: %v", err)
		}

		// Verify model
		if reqBody["model"] != "llama3" {
			t.Errorf("expected model %q, got %v", "llama3", reqBody["model"])
		}

		// Verify stream is false
		if reqBody["stream"] != false {
			t.Errorf("expected stream=false, got %v", reqBody["stream"])
		}

		// Verify format is "json"
		if reqBody["format"] != "json" {
			t.Errorf("expected format=%q, got %v", "json", reqBody["format"])
		}

		// Verify messages: should have 2 (system + user)
		messages, ok := reqBody["messages"].([]interface{})
		if !ok {
			t.Fatalf("expected messages to be an array, got %T", reqBody["messages"])
		}
		if len(messages) != 2 {
			t.Fatalf("expected 2 messages, got %d", len(messages))
		}

		msg0, _ := messages[0].(map[string]interface{})
		if msg0["role"] != "system" {
			t.Errorf("expected first message role %q, got %v", "system", msg0["role"])
		}
		if msg0["content"] != "You are a security analyst." {
			t.Errorf("expected system content %q, got %v", "You are a security analyst.", msg0["content"])
		}

		msg1, _ := messages[1].(map[string]interface{})
		if msg1["role"] != "user" {
			t.Errorf("expected second message role %q, got %v", "user", msg1["role"])
		}
		if msg1["content"] != "Analyze this binary." {
			t.Errorf("expected user content %q, got %v", "Analyze this binary.", msg1["content"])
		}

		// Verify options.num_predict is set (MaxTokens > 0)
		options, ok := reqBody["options"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected options to be present")
		}
		numPredict, ok := options["num_predict"].(float64)
		if !ok || int(numPredict) != 1024 {
			t.Errorf("expected num_predict=1024, got %v", options["num_predict"])
		}

		// Return mock response
		resp := map[string]interface{}{
			"message": map[string]interface{}{
				"role":    "assistant",
				"content": `{"verdict":"safe"}`,
			},
			"prompt_eval_count": 42,
			"eval_count":        15,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	o := NewOllama(server.URL, "llama3")
	resp, err := o.Complete(context.Background(), Request{
		SystemPrompt: "You are a security analyst.",
		UserPrompt:   "Analyze this binary.",
		MaxTokens:    1024,
	})
	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}

	if resp.Content != `{"verdict":"safe"}` {
		t.Errorf("expected content %q, got %q", `{"verdict":"safe"}`, resp.Content)
	}
	if resp.Usage.InputTokens != 42 {
		t.Errorf("expected InputTokens=42, got %d", resp.Usage.InputTokens)
	}
	if resp.Usage.OutputTokens != 15 {
		t.Errorf("expected OutputTokens=15, got %d", resp.Usage.OutputTokens)
	}
}

func TestOllamaCompleteNoMaxTokens(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		defer r.Body.Close()

		var reqBody map[string]interface{}
		json.Unmarshal(body, &reqBody)

		// options should not be present when MaxTokens is 0
		if _, ok := reqBody["options"]; ok {
			t.Errorf("expected no options when MaxTokens=0")
		}

		resp := map[string]interface{}{
			"message": map[string]interface{}{
				"role":    "assistant",
				"content": "ok",
			},
			"prompt_eval_count": 10,
			"eval_count":        5,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	o := NewOllama(server.URL, "llama3")
	_, err := o.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
		MaxTokens:    0,
	})
	if err != nil {
		t.Fatalf("Complete() returned error: %v", err)
	}
}

func TestOllamaCompleteHTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	o := NewOllama(server.URL, "llama3")
	_, err := o.Complete(context.Background(), Request{
		SystemPrompt: "sys",
		UserPrompt:   "usr",
	})
	if err == nil {
		t.Fatal("expected error for non-200 status, got nil")
	}
}

func TestOllamaDefaultBaseURL(t *testing.T) {
	o := NewOllama("", "llama3")
	if o.baseURL != "http://localhost:11434" {
		t.Errorf("expected default baseURL %q, got %q", "http://localhost:11434", o.baseURL)
	}
}
