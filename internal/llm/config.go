package llm

import (
	"time"
)

// Mode specifies when LLM analysis is performed.
type Mode string

const (
	ModeSync   Mode = "sync"   // Block until analysis completes
	ModeAsync  Mode = "async"  // Fire-and-forget, log results
	ModeHybrid Mode = "hybrid" // Sync for pre-events, async for post/stop events
)

// Config holds all LLM-related configuration.
type Config struct {
	// Enabled controls whether LLM analysis is active.
	Enabled bool `yaml:"enabled"`

	// Mode determines when analysis blocks vs runs async.
	Mode Mode `yaml:"mode"`

	// ProviderOrder specifies the fallback order for providers.
	ProviderOrder []ProviderType `yaml:"provider_order"`

	// Providers contains provider-specific configurations.
	Providers ProvidersConfig `yaml:"providers"`

	// Analysis contains analysis trigger configuration.
	Analysis AnalysisConfig `yaml:"analysis"`

	// Prompts contains custom prompt templates.
	Prompts PromptsConfig `yaml:"prompts"`

	// Cache configures response caching.
	Cache CacheConfig `yaml:"cache"`

	// RateLimit configures rate limiting.
	RateLimit RateLimitConfig `yaml:"rate_limit"`

	// Budget configures cost controls.
	Budget BudgetConfig `yaml:"budget"`

	// Timeouts configures provider timeouts.
	Timeouts TimeoutConfig `yaml:"timeouts"`
}

// ProvidersConfig contains configuration for each provider type.
type ProvidersConfig struct {
	ClaudeCLI   ClaudeCLIConfig   `yaml:"claude_cli"`
	Anthropic   AnthropicConfig   `yaml:"anthropic"`
	OpenAI      OpenAIConfig      `yaml:"openai"`
	HuggingFace HuggingFaceConfig `yaml:"huggingface"`
}

// ClaudeCLIConfig configures the Claude CLI provider.
type ClaudeCLIConfig struct {
	// Enabled controls whether this provider is active.
	Enabled bool `yaml:"enabled"`

	// BinaryPath is the path to the claude/opencode binary.
	// If empty, auto-detect from PATH.
	BinaryPath string `yaml:"binary_path"`

	// Model overrides the CLI default model.
	Model string `yaml:"model"`

	// MaxTokens limits the response length.
	MaxTokens int `yaml:"max_tokens"`
}

// AnthropicConfig configures the Anthropic API provider.
type AnthropicConfig struct {
	// Enabled controls whether this provider is active.
	Enabled bool `yaml:"enabled"`

	// APIKey is the Anthropic API key.
	// If empty, reads from ANTHROPIC_API_KEY environment variable.
	APIKey string `yaml:"api_key"`

	// Model specifies the model to use.
	Model string `yaml:"model"`

	// MaxTokens limits the response length.
	MaxTokens int `yaml:"max_tokens"`

	// BaseURL overrides the API endpoint (for proxies).
	BaseURL string `yaml:"base_url"`
}

// OpenAIConfig configures the OpenAI API provider.
type OpenAIConfig struct {
	// Enabled controls whether this provider is active.
	Enabled bool `yaml:"enabled"`

	// APIKey is the OpenAI API key.
	// If empty, reads from OPENAI_API_KEY environment variable.
	APIKey string `yaml:"api_key"`

	// Model specifies the model to use.
	Model string `yaml:"model"`

	// MaxTokens limits the response length.
	MaxTokens int `yaml:"max_tokens"`

	// BaseURL overrides the API endpoint (for Azure/proxies).
	BaseURL string `yaml:"base_url"`

	// Organization optionally specifies the organization ID.
	Organization string `yaml:"organization"`
}

// HuggingFaceConfig configures the HuggingFace Inference API provider.
type HuggingFaceConfig struct {
	// Enabled controls whether this provider is active.
	Enabled bool `yaml:"enabled"`

	// APIKey is the HuggingFace API token.
	// If empty, reads from HUGGINGFACE_API_KEY environment variable.
	APIKey string `yaml:"api_key"`

	// Model specifies the model to use.
	Model string `yaml:"model"`

	// MaxTokens limits the response length.
	MaxTokens int `yaml:"max_tokens"`

	// BaseURL overrides the inference endpoint.
	BaseURL string `yaml:"base_url"`
}

// AnalysisConfig configures when and how to trigger LLM analysis.
type AnalysisConfig struct {
	// EventTypes lists which event types can trigger analysis.
	EventTypes []string `yaml:"event_types"`

	// MinConfidence is the minimum confidence to trust LLM decisions.
	MinConfidence float32 `yaml:"min_confidence"`

	// Triggers defines specific conditions for triggering analysis.
	Triggers []AnalysisTrigger `yaml:"triggers"`
}

// AnalysisTrigger defines conditions for triggering LLM analysis.
type AnalysisTrigger struct {
	// EventType is the event type this trigger applies to.
	EventType string `yaml:"event_type"`

	// Conditions specifies when to trigger.
	Conditions TriggerConditions `yaml:"conditions"`

	// AnalysisTypes specifies which analyses to perform.
	AnalysisTypes []AnalysisType `yaml:"analysis_types"`

	// Mode overrides the global mode for this trigger.
	Mode Mode `yaml:"mode"`
}

// TriggerConditions specifies conditions for triggering analysis.
type TriggerConditions struct {
	// Always triggers unconditionally if true.
	Always bool `yaml:"always"`

	// ToolNames is a list of regex patterns to match tool names.
	ToolNames []string `yaml:"tool_names"`

	// NoRuleMatch triggers when no rules matched.
	NoRuleMatch bool `yaml:"no_rule_match"`

	// RuleDecision triggers on specific rule decisions.
	RuleDecision []string `yaml:"rule_decision"`

	// MinToolInputSize triggers for large tool inputs.
	MinToolInputSize int `yaml:"min_tool_input_size"`
}

// CacheConfig configures response caching.
type CacheConfig struct {
	// Enabled controls whether caching is active.
	Enabled bool `yaml:"enabled"`

	// MaxEntries is the maximum number of cached responses.
	MaxEntries int `yaml:"max_entries"`

	// TTL is the time-to-live for cached entries.
	TTL time.Duration `yaml:"ttl"`
}

// RateLimitConfig configures rate limiting.
type RateLimitConfig struct {
	// Enabled controls whether rate limiting is active.
	Enabled bool `yaml:"enabled"`

	// RequestsPerMin is the maximum requests per minute.
	RequestsPerMin int `yaml:"requests_per_min"`

	// BurstSize allows temporary bursts above the rate.
	BurstSize int `yaml:"burst_size"`
}

// BudgetConfig configures cost controls.
type BudgetConfig struct {
	// Enabled controls whether budget tracking is active.
	Enabled bool `yaml:"enabled"`

	// DailyLimitCents is the maximum daily spend in cents.
	DailyLimitCents int `yaml:"daily_limit_cents"`

	// WarnAtPercent triggers a warning at this percentage of budget.
	WarnAtPercent int `yaml:"warn_at_percent"`

	// AlertOnExceed sends an alert when budget is exceeded.
	AlertOnExceed bool `yaml:"alert_on_exceed"`
}

// TimeoutConfig configures provider timeouts.
type TimeoutConfig struct {
	// CLI is the timeout for CLI-based providers.
	CLI time.Duration `yaml:"cli"`

	// API is the timeout for API-based providers.
	API time.Duration `yaml:"api"`
}

// PromptsConfig contains custom prompt templates for LLM analysis.
// If a prompt is empty, the default built-in prompt will be used.
type PromptsConfig struct {
	// SystemPrompt is prepended to all analysis prompts.
	// Use this to set the overall role and response format expectations.
	SystemPrompt string `yaml:"system_prompt"`

	// Contextual is the prompt template for contextual analysis (PreToolUse).
	// Available placeholders: {{.EventType}}, {{.ToolName}}, {{.ToolInput}}, {{.Cwd}}
	Contextual string `yaml:"contextual"`

	// IntentAction is the prompt template for intent vs action analysis (PostToolUse).
	// Available placeholders: {{.ToolName}}, {{.ToolInput}}, {{.ToolResponse}}
	IntentAction string `yaml:"intent_action"`

	// Transcript is the prompt template for full session transcript analysis.
	// Available placeholders: {{.SessionID}}, {{.TranscriptPath}}
	Transcript string `yaml:"transcript"`

	// Stop is the prompt template for stop event analysis.
	// Available placeholders: {{.SessionID}}, {{.TranscriptPath}}
	Stop string `yaml:"stop"`

	// UserPrompt is the prompt template for user prompt analysis.
	// Available placeholders: {{.Prompt}}, {{.Cwd}}
	UserPrompt string `yaml:"user_prompt"`
}

// DefaultConfig returns the default LLM configuration.
func DefaultConfig() *Config {
	return &Config{
		Enabled: false,
		Mode:    ModeHybrid,
		ProviderOrder: []ProviderType{
			ProviderClaudeCLI,
			ProviderAnthropic,
			ProviderOpenAI,
		},
		Providers: ProvidersConfig{
			ClaudeCLI: ClaudeCLIConfig{
				Enabled:   true,
				MaxTokens: 1024,
			},
			Anthropic: AnthropicConfig{
				Enabled:   true,
				Model:     "claude-sonnet-4-20250514",
				MaxTokens: 1024,
			},
			OpenAI: OpenAIConfig{
				Enabled:   false,
				Model:     "gpt-4-turbo",
				MaxTokens: 1024,
			},
			HuggingFace: HuggingFaceConfig{
				Enabled:   false,
				MaxTokens: 1024,
			},
		},
		Analysis: AnalysisConfig{
			EventTypes:    []string{"PreToolUse", "PostToolUse", "Stop"},
			MinConfidence: 0.7,
			Triggers: []AnalysisTrigger{
				{
					EventType: "PreToolUse",
					Conditions: TriggerConditions{
						ToolNames:   []string{"^Bash$"},
						NoRuleMatch: true,
					},
					AnalysisTypes: []AnalysisType{AnalysisContextual},
					Mode:          ModeSync,
				},
				{
					EventType: "Stop",
					Conditions: TriggerConditions{
						Always: true,
					},
					AnalysisTypes: []AnalysisType{AnalysisStop, AnalysisTranscript},
					Mode:          ModeAsync,
				},
			},
		},
		Cache: CacheConfig{
			Enabled:    true,
			MaxEntries: 1000,
			TTL:        5 * time.Minute,
		},
		RateLimit: RateLimitConfig{
			Enabled:        true,
			RequestsPerMin: 60,
			BurstSize:      10,
		},
		Budget: BudgetConfig{
			Enabled:         true,
			DailyLimitCents: 500,
			WarnAtPercent:   80,
			AlertOnExceed:   true,
		},
		Timeouts: TimeoutConfig{
			CLI: 60 * time.Second,
			API: 15 * time.Second,
		},
	}
}

// Validate validates the LLM configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil // No validation needed if disabled
	}

	// Validate mode
	switch c.Mode {
	case ModeSync, ModeAsync, ModeHybrid:
		// Valid
	default:
		return &ConfigError{Field: "mode", Message: "must be 'sync', 'async', or 'hybrid'"}
	}

	// Validate provider order contains only valid types
	validTypes := map[ProviderType]bool{
		ProviderClaudeCLI:   true,
		ProviderAnthropic:   true,
		ProviderOpenAI:      true,
		ProviderHuggingFace: true,
	}
	for _, pt := range c.ProviderOrder {
		if !validTypes[pt] {
			return &ConfigError{Field: "provider_order", Message: "invalid provider type: " + string(pt)}
		}
	}

	// Validate confidence range
	if c.Analysis.MinConfidence < 0 || c.Analysis.MinConfidence > 1 {
		return &ConfigError{Field: "analysis.min_confidence", Message: "must be between 0 and 1"}
	}

	// Validate timeouts are positive
	if c.Timeouts.CLI <= 0 {
		return &ConfigError{Field: "timeouts.cli", Message: "must be positive"}
	}
	if c.Timeouts.API <= 0 {
		return &ConfigError{Field: "timeouts.api", Message: "must be positive"}
	}

	return nil
}

// ConfigError represents a configuration error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "llm config error: " + e.Field + ": " + e.Message
}
