// Package llm provides multi-provider LLM integration for semantic analysis of hook events.
package llm

import (
	"context"
	"time"

	"github.com/ihavespoons/hooksy/internal/hooks"
)

// ProviderType identifies the LLM provider.
type ProviderType string

const (
	ProviderClaudeCLI   ProviderType = "claude_cli"
	ProviderAnthropic   ProviderType = "anthropic"
	ProviderOpenAI      ProviderType = "openai"
	ProviderHuggingFace ProviderType = "huggingface"
)

// AnalysisType specifies the kind of analysis to perform.
type AnalysisType string

const (
	AnalysisTranscript   AnalysisType = "transcript"     // Full conversation analysis
	AnalysisIntentAction AnalysisType = "intent_action"  // Pre vs Post tool comparison
	AnalysisContextual   AnalysisType = "contextual"     // Is this suspicious in context?
	AnalysisStop         AnalysisType = "stop"           // Session termination analysis
	AnalysisCustom       AnalysisType = "custom"         // Custom prompt completion (for CTVP)
)

// AnalysisDecision represents the LLM's recommendation.
type AnalysisDecision string

const (
	DecisionAllow AnalysisDecision = "allow"
	DecisionDeny  AnalysisDecision = "deny"
	DecisionAsk   AnalysisDecision = "ask"
	DecisionBlock AnalysisDecision = "block"
)

// Provider defines the interface for LLM providers.
type Provider interface {
	// Type returns the provider type identifier.
	Type() ProviderType

	// Name returns the human-readable provider name.
	Name() string

	// Available checks if the provider is currently available and configured.
	Available(ctx context.Context) bool

	// Analyze performs analysis on the given request.
	Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error)

	// EstimateCost estimates the cost in cents for analyzing the request.
	EstimateCost(req *AnalysisRequest) float64

	// Close releases any resources held by the provider.
	Close() error
}

// AnalysisRequest contains the data to be analyzed.
type AnalysisRequest struct {
	// Type specifies the kind of analysis to perform.
	Type AnalysisType

	// EventType is the hook event type being analyzed.
	EventType hooks.EventType

	// SessionID identifies the session.
	SessionID string

	// TranscriptPath is the path to the session transcript file.
	TranscriptPath string

	// ToolName is the name of the tool (for tool events).
	ToolName string

	// ToolInput contains the tool input parameters.
	ToolInput map[string]interface{}

	// ToolResponse contains the tool response (for PostToolUse).
	ToolResponse map[string]interface{}

	// ToolUseID correlates Pre and PostToolUse events.
	ToolUseID string

	// Prompt is the user prompt (for UserPromptSubmit).
	Prompt string

	// Context provides additional context for analysis.
	Context *AnalysisContext

	// RuleEvaluation contains the rule-based evaluation result for cross-validation.
	RuleDecision string
	RuleReason   string

	// CustomPrompt allows overriding the default prompt template.
	// If set, this prompt is used directly instead of the built-in prompts.
	CustomPrompt string

	// SystemPrompt is prepended to the analysis prompt if set.
	SystemPrompt string

	// UserPrompt is the user-provided prompt for custom analysis (AnalysisCustom).
	UserPrompt string
}

// AnalysisContext provides contextual information for analysis.
type AnalysisContext struct {
	// Cwd is the current working directory.
	Cwd string

	// ProjectType hints at the project type (e.g., "go", "python", "node").
	ProjectType string

	// RecentTools lists recently used tools in this session.
	RecentTools []string

	// RecentCommands lists recently executed commands.
	RecentCommands []string

	// SessionDuration is how long the session has been active.
	SessionDuration time.Duration

	// ToolCallCount is the number of tool calls in this session.
	ToolCallCount int
}

// AnalysisResponse contains the LLM's analysis result.
type AnalysisResponse struct {
	// Decision is the recommended action.
	Decision AnalysisDecision

	// Confidence is the confidence level (0.0-1.0).
	Confidence float32

	// Reasoning explains the decision.
	Reasoning string

	// Findings contains specific issues found.
	Findings []Finding

	// ProviderType identifies which provider produced this response.
	ProviderType ProviderType

	// TokensUsed is the number of tokens consumed.
	TokensUsed int

	// Latency is how long the analysis took.
	Latency time.Duration

	// CostCents is the estimated cost in cents.
	CostCents float64

	// Cached indicates if this response came from cache.
	Cached bool

	// RawResponse contains the raw text response for custom analysis.
	RawResponse string
}

// Finding represents a specific issue found during analysis.
type Finding struct {
	// Category classifies the finding (e.g., "deception", "data_exfiltration", "unauthorized_action").
	Category string

	// Severity indicates the severity level (e.g., "low", "medium", "high", "critical").
	Severity string

	// Description explains the finding.
	Description string

	// Evidence contains relevant evidence from the input.
	Evidence string

	// Location specifies where the issue was found (e.g., field name, line number).
	Location string
}

// FindingCategory constants for categorizing findings.
const (
	CategoryDeception        = "deception"
	CategoryGoalHijacking    = "goal_hijacking"
	CategoryDataExfiltration = "data_exfiltration"
	CategoryUnauthorized     = "unauthorized_action"
	CategorySandbagging      = "sandbagging"
	CategoryInjection        = "injection"
	CategorySuspiciousExit   = "suspicious_exit"
)

// SeverityLevel constants.
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)
