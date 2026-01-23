package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/ihavespoons/hooksy/internal/llm"
)

const (
	defaultHuggingFaceURL = "https://api-inference.huggingface.co/models/"
)

// HuggingFaceProvider implements the Provider interface using HuggingFace Inference API.
type HuggingFaceProvider struct {
	apiKey    string
	model     string
	maxTokens int
	baseURL   string
	client    *http.Client
	available bool
	mu        sync.RWMutex
}

// NewHuggingFaceProvider creates a new HuggingFace Inference API provider.
func NewHuggingFaceProvider(cfg *llm.Config) (llm.Provider, error) {
	apiCfg := cfg.Providers.HuggingFace
	if !apiCfg.Enabled {
		return nil, fmt.Errorf("huggingface provider is disabled")
	}

	p := &HuggingFaceProvider{
		apiKey:    apiCfg.APIKey,
		model:     apiCfg.Model,
		maxTokens: apiCfg.MaxTokens,
		baseURL:   apiCfg.BaseURL,
		client:    &http.Client{},
	}

	// Use environment variable if API key not set
	if p.apiKey == "" {
		p.apiKey = os.Getenv("HUGGINGFACE_API_KEY")
	}
	// Also try the common HF token env var
	if p.apiKey == "" {
		p.apiKey = os.Getenv("HF_TOKEN")
	}

	// Set defaults
	if p.maxTokens == 0 {
		p.maxTokens = 1024
	}
	if p.baseURL == "" {
		p.baseURL = defaultHuggingFaceURL
	}

	// Check availability - need both API key and model
	p.available = p.apiKey != "" && p.model != ""

	return p, nil
}

// Type returns the provider type.
func (p *HuggingFaceProvider) Type() llm.ProviderType {
	return llm.ProviderHuggingFace
}

// Name returns the human-readable provider name.
func (p *HuggingFaceProvider) Name() string {
	if p.model != "" {
		return fmt.Sprintf("HuggingFace (%s)", p.model)
	}
	return "HuggingFace Inference API"
}

// Available checks if the provider is available.
func (p *HuggingFaceProvider) Available(ctx context.Context) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.available
}

// Analyze performs analysis using the HuggingFace Inference API.
func (p *HuggingFaceProvider) Analyze(ctx context.Context, req *llm.AnalysisRequest) (*llm.AnalysisResponse, error) {
	if !p.available {
		return nil, fmt.Errorf("huggingface API is not available (missing API key or model)")
	}

	// Build the prompt
	prompt := buildAnalysisPrompt(req)

	// Create API request for text generation
	apiReq := huggingFaceRequest{
		Inputs: prompt,
		Parameters: huggingFaceParameters{
			MaxNewTokens:  p.maxTokens,
			Temperature:   0.1,
			ReturnFullText: false,
		},
	}

	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Build URL with model
	url := p.baseURL + p.model

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)

	// Send request
	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp huggingFaceError
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	// Parse response - HuggingFace returns an array
	var apiResp []huggingFaceResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		// Try parsing as single object
		var singleResp huggingFaceResponse
		if err := json.Unmarshal(body, &singleResp); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}
		apiResp = []huggingFaceResponse{singleResp}
	}

	if len(apiResp) == 0 {
		return nil, fmt.Errorf("no response from API")
	}

	// Extract text content
	text := apiResp[0].GeneratedText
	if text == "" {
		return nil, fmt.Errorf("no generated text in response")
	}

	// Parse the text response
	analysisResp, err := parseStructuredOrTextResponse(text, llm.ProviderHuggingFace)
	if err != nil {
		return nil, err
	}

	// HuggingFace Inference API doesn't provide token counts
	// Estimate based on text length
	analysisResp.TokensUsed = (len(prompt) + len(text)) / 4

	// HuggingFace pricing varies, estimate conservatively
	analysisResp.CostCents = p.EstimateCost(req)

	return analysisResp, nil
}

// EstimateCost estimates the cost for analysis.
func (p *HuggingFaceProvider) EstimateCost(req *llm.AnalysisRequest) float64 {
	// HuggingFace Inference API pricing varies
	// Many models are free, but some have costs
	// For now, estimate very low cost
	prompt := buildAnalysisPrompt(req)
	tokens := (len(prompt) + p.maxTokens) / 4

	// Estimate $0.0001 per 1000 tokens (very rough)
	return float64(tokens) * 0.0001 / 10
}

// Close releases any resources.
func (p *HuggingFaceProvider) Close() error {
	return nil
}

// huggingFaceRequest represents the API request structure.
type huggingFaceRequest struct {
	Inputs     string                 `json:"inputs"`
	Parameters huggingFaceParameters  `json:"parameters,omitempty"`
}

// huggingFaceParameters represents generation parameters.
type huggingFaceParameters struct {
	MaxNewTokens   int     `json:"max_new_tokens,omitempty"`
	Temperature    float64 `json:"temperature,omitempty"`
	ReturnFullText bool    `json:"return_full_text,omitempty"`
	DoSample       bool    `json:"do_sample,omitempty"`
}

// huggingFaceResponse represents the API response structure.
type huggingFaceResponse struct {
	GeneratedText string `json:"generated_text"`
}

// huggingFaceError represents an API error response.
type huggingFaceError struct {
	Error         string   `json:"error"`
	EstimatedTime float64  `json:"estimated_time,omitempty"`
	Warnings      []string `json:"warnings,omitempty"`
}
