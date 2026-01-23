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
	defaultOpenAIURL   = "https://api.openai.com/v1/chat/completions"
	defaultOpenAIModel = "gpt-4-turbo"
)

// OpenAIProvider implements the Provider interface using OpenAI's Chat Completions API.
type OpenAIProvider struct {
	apiKey       string
	model        string
	maxTokens    int
	baseURL      string
	organization string
	client       *http.Client
	available    bool
	mu           sync.RWMutex
}

// NewOpenAIProvider creates a new OpenAI API provider.
func NewOpenAIProvider(cfg *llm.Config) (llm.Provider, error) {
	apiCfg := cfg.Providers.OpenAI
	if !apiCfg.Enabled {
		return nil, fmt.Errorf("openai provider is disabled")
	}

	p := &OpenAIProvider{
		apiKey:       apiCfg.APIKey,
		model:        apiCfg.Model,
		maxTokens:    apiCfg.MaxTokens,
		baseURL:      apiCfg.BaseURL,
		organization: apiCfg.Organization,
		client:       &http.Client{},
	}

	// Use environment variable if API key not set
	if p.apiKey == "" {
		p.apiKey = os.Getenv("OPENAI_API_KEY")
	}

	// Set defaults
	if p.model == "" {
		p.model = defaultOpenAIModel
	}
	if p.maxTokens == 0 {
		p.maxTokens = 1024
	}
	if p.baseURL == "" {
		p.baseURL = defaultOpenAIURL
	}

	// Check availability
	p.available = p.apiKey != ""

	return p, nil
}

// Type returns the provider type.
func (p *OpenAIProvider) Type() llm.ProviderType {
	return llm.ProviderOpenAI
}

// Name returns the human-readable provider name.
func (p *OpenAIProvider) Name() string {
	return fmt.Sprintf("OpenAI API (%s)", p.model)
}

// Available checks if the provider is available.
func (p *OpenAIProvider) Available(ctx context.Context) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.available
}

// Analyze performs analysis using the OpenAI API.
func (p *OpenAIProvider) Analyze(ctx context.Context, req *llm.AnalysisRequest) (*llm.AnalysisResponse, error) {
	if !p.available {
		return nil, fmt.Errorf("openai API is not available (missing API key)")
	}

	// Build the prompt
	prompt := buildAnalysisPrompt(req)

	// Create API request
	apiReq := openAIRequest{
		Model: p.model,
		Messages: []openAIMessage{
			{
				Role:    "system",
				Content: "You are a security analyzer for an AI coding assistant. Respond only with valid JSON.",
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
		MaxTokens:   p.maxTokens,
		Temperature: 0.1, // Low temperature for consistent analysis
	}

	reqBody, err := json.Marshal(apiReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.baseURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.apiKey)
	if p.organization != "" {
		httpReq.Header.Set("OpenAI-Organization", p.organization)
	}

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
		var errResp openAIErrorResponse
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp openAIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if len(apiResp.Choices) == 0 {
		return nil, fmt.Errorf("no choices in response")
	}

	// Extract text content
	text := apiResp.Choices[0].Message.Content
	if text == "" {
		return nil, fmt.Errorf("no content in response")
	}

	// Parse the text response
	analysisResp, err := parseStructuredOrTextResponse(text, llm.ProviderOpenAI)
	if err != nil {
		return nil, err
	}

	// Add token usage
	analysisResp.TokensUsed = apiResp.Usage.TotalTokens

	// Estimate cost
	analysisResp.CostCents = p.estimateCostFromTokens(apiResp.Usage.PromptTokens, apiResp.Usage.CompletionTokens)

	return analysisResp, nil
}

// EstimateCost estimates the cost for analysis.
func (p *OpenAIProvider) EstimateCost(req *llm.AnalysisRequest) float64 {
	// Rough estimate based on prompt size
	prompt := buildAnalysisPrompt(req)
	inputTokens := len(prompt) / 4  // Rough estimate: 4 chars per token
	outputTokens := p.maxTokens / 2 // Assume half of max tokens used

	return p.estimateCostFromTokens(inputTokens, outputTokens)
}

// estimateCostFromTokens calculates cost from token counts.
func (p *OpenAIProvider) estimateCostFromTokens(inputTokens, outputTokens int) float64 {
	// Pricing varies by model (as of 2024)
	var inputRate, outputRate float64

	switch p.model {
	case "gpt-4-turbo", "gpt-4-turbo-preview":
		inputRate = 10.0 / 1_000_000
		outputRate = 30.0 / 1_000_000
	case "gpt-4":
		inputRate = 30.0 / 1_000_000
		outputRate = 60.0 / 1_000_000
	case "gpt-4o":
		inputRate = 5.0 / 1_000_000
		outputRate = 15.0 / 1_000_000
	case "gpt-4o-mini":
		inputRate = 0.15 / 1_000_000
		outputRate = 0.6 / 1_000_000
	case "gpt-3.5-turbo":
		inputRate = 0.5 / 1_000_000
		outputRate = 1.5 / 1_000_000
	default:
		// Default to GPT-4 Turbo pricing
		inputRate = 10.0 / 1_000_000
		outputRate = 30.0 / 1_000_000
	}

	costDollars := (float64(inputTokens) * inputRate) + (float64(outputTokens) * outputRate)
	return costDollars * 100 // Convert to cents
}

// Close releases any resources.
func (p *OpenAIProvider) Close() error {
	return nil
}

// openAIRequest represents the API request structure.
type openAIRequest struct {
	Model       string          `json:"model"`
	Messages    []openAIMessage `json:"messages"`
	MaxTokens   int             `json:"max_tokens,omitempty"`
	Temperature float64         `json:"temperature,omitempty"`
}

// openAIMessage represents a message in the conversation.
type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// openAIResponse represents the API response structure.
type openAIResponse struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Created int64          `json:"created"`
	Model   string         `json:"model"`
	Choices []openAIChoice `json:"choices"`
	Usage   openAIUsage    `json:"usage"`
}

// openAIChoice represents a choice in the response.
type openAIChoice struct {
	Index        int           `json:"index"`
	Message      openAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

// openAIUsage represents token usage.
type openAIUsage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// openAIErrorResponse represents an API error response.
type openAIErrorResponse struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
}
