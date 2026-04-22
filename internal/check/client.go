package check

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ariary/soa/pkg/checkapi"
)

type ProgressFunc func(progress float64)

type Client struct {
	baseURL      string
	timeout      time.Duration
	pollInterval time.Duration
	httpClient   *http.Client
}

func NewClient(baseURL string, timeout, pollInterval time.Duration) *Client {
	return &Client{
		baseURL:      baseURL,
		timeout:      timeout,
		pollInterval: pollInterval,
		httpClient:   &http.Client{Timeout: timeout},
	}
}

func (c *Client) Check(ctx context.Context, req checkapi.CheckRequest) (checkapi.CheckResponse, error) {
	return c.CheckWithProgress(ctx, req, nil)
}

func (c *Client) CheckWithProgress(ctx context.Context, req checkapi.CheckRequest, onProgress ProgressFunc) (checkapi.CheckResponse, error) {
	blocked := checkapi.CheckResponse{Status: checkapi.StatusBlocked, Reason: "check failed"}

	body, err := json.Marshal(req)
	if err != nil {
		return blocked, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/check", bytes.NewReader(body))
	if err != nil {
		return blocked, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return blocked, fmt.Errorf("check request: %w", err)
	}
	defer httpResp.Body.Close()

	var resp checkapi.CheckResponse
	if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
		return blocked, fmt.Errorf("decode response: %w", err)
	}

	if resp.Status != checkapi.StatusProcessing {
		return resp, nil
	}

	if onProgress != nil {
		onProgress(resp.Progress)
	}
	return c.poll(ctx, resp.ID, onProgress)
}

func (c *Client) poll(ctx context.Context, id string, onProgress ProgressFunc) (checkapi.CheckResponse, error) {
	blocked := checkapi.CheckResponse{Status: checkapi.StatusBlocked, Reason: "check failed"}
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return blocked, ctx.Err()
		case <-ticker.C:
			httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/check/%s", c.baseURL, id), nil)
			if err != nil {
				return blocked, err
			}
			httpResp, err := c.httpClient.Do(httpReq)
			if err != nil {
				return blocked, fmt.Errorf("poll request: %w", err)
			}
			var resp checkapi.CheckResponse
			err = json.NewDecoder(httpResp.Body).Decode(&resp)
			httpResp.Body.Close()
			if err != nil {
				return blocked, fmt.Errorf("decode poll response: %w", err)
			}

			if onProgress != nil && resp.Status == checkapi.StatusProcessing {
				onProgress(resp.Progress)
			}
			if resp.Status != checkapi.StatusProcessing {
				return resp, nil
			}
		}
	}
}
