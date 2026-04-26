// Package client implements the Go-side stub of the proxy → ML scoring call.
// Failure of the ML service must NEVER block traffic — the caller is expected
// to fall back to rule-only mode (SRS REL-2 safe-mode requirement).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/shaheerkj/latentguard/proxy/internal/normalizer"
)

// ScoreRequest mirrors ml/app/schemas.py:ScoreRequest.
type ScoreRequest struct {
	RequestID      string              `json:"request_id"`
	Method         string              `json:"method"`
	Path           string              `json:"path"`
	CanonicalPath  string              `json:"canonical_path"`
	CanonicalQuery string              `json:"canonical_query"`
	CanonicalBody  string              `json:"canonical_body"`
	Features       normalizer.Features `json:"features"`
	RuleScore      float64             `json:"rule_score"`
	RuleMatched    []string            `json:"rule_matched"`
}

// ScoreResponse mirrors ml/app/schemas.py:ScoreResponse.
type ScoreResponse struct {
	Action        string   `json:"action"`
	Score         float64  `json:"score"`
	AnomalyScore  float64  `json:"anomaly_score"`
	OutlierScore  float64  `json:"outlier_score"`
	RuleScore     float64  `json:"rule_score"`
	Reasons       []string `json:"reasons"`
	FallbackUsed  bool     `json:"fallback_used"`
}

// MLClient is the proxy's only network dependency on the Python service.
type MLClient struct {
	baseURL string
	http    *http.Client
}

// New builds an MLClient with sensible timeouts for an in-the-loop hot path.
func New(baseURL string, timeout time.Duration) *MLClient {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	return &MLClient{
		baseURL: baseURL,
		http: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 50,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Score posts a normalized request and returns the ML decision. Any error
// returned here should trigger safe-mode fallback in the caller.
func (c *MLClient) Score(ctx context.Context, req ScoreRequest) (*ScoreResponse, error) {
	buf, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal score request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/score", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("ml service status %d: %s", resp.StatusCode, string(body))
	}

	var out ScoreResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode score response: %w", err)
	}
	return &out, nil
}

// Healthy returns true if the ML service answers /healthz within timeout.
// Used by the proxy's heartbeat goroutine for safe-mode toggling.
func (c *MLClient) Healthy(ctx context.Context) bool {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return false
	}
	resp, err := c.http.Do(httpReq)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
