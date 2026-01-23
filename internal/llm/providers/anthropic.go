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
	defaultAnthropicURL     = "https://api.anthropic.com/v1/messages"
	defaultAnthropicModel   = "claude-sonnet-4-20250514"
	anthropicAPIVersion     = "2023-06-01"
)

// AnthropicProvider implements the Provider interface using Anthropic's Messages API.
type AnthropicProvider struct {
	apiKey    string
	model     string
	maxTokens int
	baseURL   string
	client    *http.Client
	available bool
	mu        sync.RWMutex
}

// NewAnthropicProvider creates a new Anthropic API provider.
func NewAnthropicProvider(cfg *llm.Config) (llm.Provider, error) {
	apiCfg := cfg.Providers.Anthropic
	if !apiCfg.Enabled {
		return nil, fmt.Errorf("anthropic provider is disabled")
	}

	p := &AnthropicProvider{
		apiKey:    apiCfg.APIKey,
		model:     apiCfg.Model,
		maxTokens: apiCfg.MaxTokens,
		baseURL:   apiCfg.BaseURL,
		client:    &http.Client{},
	}

	// Use environment variable if API key not set
	if p.apiKey == "" {
		p.apiKey = os.Getenv("ANTHROPIC_API_KEY")
	}

	// Set defaults
	if p.model == "" {
		p.model = defaultAnthropicModel
	}
	if p.maxTokens == 0 {
		p.maxTokens = 1024
	}
	if p.baseURL == "" {
		p.baseURL = defaultAnthropicURL
	}

	// Check availability
	p.available = p.apiKey != ""

	return p, nil
}

// Type returns the provider type.
func (p *AnthropicProvider) Type() llm.ProviderType {
	return llm.ProviderAnthropic
}

// Name returns the human-readable provider name.
func (p *AnthropicProvider) Name() string {
	return fmt.Sprintf("Anthropic API (%s)", p.model)
}

// Available checks if the provider is available.
func (p *AnthropicProvider) Available(ctx context.Context) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.available
}

// Analyze performs analysis using the Anthropic API.
func (p *AnthropicProvider) Analyze(ctx context.Context, req *llm.AnalysisRequest) (*llm.AnalysisResponse, error) {
	if !p.available {
		return nil, fmt.Errorf("anthropic API is not available (missing API key)")
	}

	// Build the prompt
	prompt := buildAnalysisPrompt(req)

	// Create API request
	apiReq := anthropicRequest{
		Model:     p.model,
		MaxTokens: p.maxTokens,
		Messages: []anthropicMessage{
			{
				Role:    "user",
				Content: prompt,
			},
		},
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
	httpReq.Header.Set("x-api-key", p.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicAPIVersion)

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
		var errResp anthropicError
		if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error.Message != "" {
			return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var apiResp anthropicResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract text content
	var text string
	for _, content := range apiResp.Content {
		if content.Type == "text" {
			text = content.Text
			break
		}
	}

	if text == "" {
		return nil, fmt.Errorf("no text content in response")
	}

	// Parse the text response
	analysisResp, err := parseStructuredOrTextResponse(text, llm.ProviderAnthropic)
	if err != nil {
		return nil, err
	}

	// Add token usage
	analysisResp.TokensUsed = apiResp.Usage.InputTokens + apiResp.Usage.OutputTokens

	// Estimate cost
	analysisResp.CostCents = p.estimateCostFromTokens(apiResp.Usage.InputTokens, apiResp.Usage.OutputTokens)

	return analysisResp, nil
}

// EstimateCost estimates the cost for analysis.
func (p *AnthropicProvider) EstimateCost(req *llm.AnalysisRequest) float64 {
	// Rough estimate based on prompt size
	prompt := buildAnalysisPrompt(req)
	inputTokens := len(prompt) / 4  // Rough estimate: 4 chars per token
	outputTokens := p.maxTokens / 2 // Assume half of max tokens used

	return p.estimateCostFromTokens(inputTokens, outputTokens)
}

// estimateCostFromTokens calculates cost from token counts.
func (p *AnthropicProvider) estimateCostFromTokens(inputTokens, outputTokens int) float64 {
	// Pricing varies by model (as of 2024)
	// Claude Sonnet: $3/M input, $15/M output
	// Claude Haiku: $0.25/M input, $1.25/M output
	var inputRate, outputRate float64

	switch p.model {
	case "claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022":
		inputRate = 3.0 / 1_000_000
		outputRate = 15.0 / 1_000_000
	case "claude-3-haiku-20240307":
		inputRate = 0.25 / 1_000_000
		outputRate = 1.25 / 1_000_000
	default:
		// Default to Sonnet pricing
		inputRate = 3.0 / 1_000_000
		outputRate = 15.0 / 1_000_000
	}

	costDollars := (float64(inputTokens) * inputRate) + (float64(outputTokens) * outputRate)
	return costDollars * 100 // Convert to cents
}

// Close releases any resources.
func (p *AnthropicProvider) Close() error {
	return nil
}

// anthropicRequest represents the API request structure.
type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

// anthropicMessage represents a message in the conversation.
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// anthropicResponse represents the API response structure.
type anthropicResponse struct {
	ID           string              `json:"id"`
	Type         string              `json:"type"`
	Role         string              `json:"role"`
	Content      []anthropicContent  `json:"content"`
	Model        string              `json:"model"`
	StopReason   string              `json:"stop_reason"`
	StopSequence *string             `json:"stop_sequence"`
	Usage        anthropicUsage      `json:"usage"`
}

// anthropicContent represents content in the response.
type anthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// anthropicUsage represents token usage.
type anthropicUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// anthropicError represents an API error response.
type anthropicError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// parseStructuredOrTextResponse tries to parse as JSON first, then falls back to text.
func parseStructuredOrTextResponse(text string, providerType llm.ProviderType) (*llm.AnalysisResponse, error) {
	// First try to parse as JSON
	var structured StructuredAnalysisResponse
	if err := json.Unmarshal([]byte(text), &structured); err == nil && structured.Decision != "" {
		return &llm.AnalysisResponse{
			Decision:     llm.AnalysisDecision(structured.Decision),
			Confidence:   structured.Confidence,
			Reasoning:    structured.Reasoning,
			Findings:     convertFindings(structured.Findings),
			ProviderType: providerType,
		}, nil
	}

	// Try to find JSON within the text (LLMs sometimes add surrounding text)
	if start := findJSONStart(text); start >= 0 {
		if end := findJSONEnd(text, start); end > start {
			jsonText := text[start : end+1]
			if err := json.Unmarshal([]byte(jsonText), &structured); err == nil && structured.Decision != "" {
				return &llm.AnalysisResponse{
					Decision:     llm.AnalysisDecision(structured.Decision),
					Confidence:   structured.Confidence,
					Reasoning:    structured.Reasoning,
					Findings:     convertFindings(structured.Findings),
					ProviderType: providerType,
				}, nil
			}
		}
	}

	// Fall back to text parsing
	return parseTextResponse(text, providerType)
}

// findJSONStart finds the start of a JSON object in text.
func findJSONStart(text string) int {
	for i, c := range text {
		if c == '{' {
			return i
		}
	}
	return -1
}

// findJSONEnd finds the matching closing brace.
func findJSONEnd(text string, start int) int {
	depth := 0
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
