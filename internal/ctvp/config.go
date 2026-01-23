package ctvp

import (
	"fmt"
	"time"
)

// Mode specifies when CTVP analysis is performed
type Mode string

const (
	ModeSync   Mode = "sync"   // Block until analysis completes
	ModeAsync  Mode = "async"  // Fire-and-forget, log results
	ModeHybrid Mode = "hybrid" // Sync for high-risk, async for low-risk
)

// Config holds all CTVP-related configuration
type Config struct {
	// Enabled controls whether CTVP analysis is active
	Enabled bool `yaml:"enabled"`

	// Mode determines when analysis blocks vs runs async
	Mode Mode `yaml:"mode"`

	// Orbit configures semantic orbit generation
	Orbit OrbitConfig `yaml:"orbit"`

	// Trace configures execution trace prediction
	Trace TraceConfig `yaml:"trace"`

	// Similarity configures cross-trace similarity metrics
	Similarity SimilarityConfig `yaml:"similarity"`

	// Threshold configures decision thresholds
	Threshold ThresholdConfig `yaml:"threshold"`

	// Triggers defines when CTVP analysis is invoked
	Triggers []TriggerConfig `yaml:"triggers"`

	// Budget configures cost controls
	Budget BudgetConfig `yaml:"budget"`

	// Timeout is the maximum time for a single analysis
	Timeout time.Duration `yaml:"timeout"`

	// Cache configures result caching
	Cache CacheConfig `yaml:"cache"`
}

// OrbitConfig configures semantic orbit generation
type OrbitConfig struct {
	// Size is the number of variants to generate
	Size int `yaml:"size"`

	// MinSize is the minimum variants needed for valid analysis
	MinSize int `yaml:"min_size"`

	// Transformations lists which transformations to apply
	Transformations []TransformationType `yaml:"transformations"`

	// MaxTransformAttempts limits retries for failed transformations
	MaxTransformAttempts int `yaml:"max_transform_attempts"`
}

// TraceConfig configures execution trace prediction
type TraceConfig struct {
	// MaxSteps limits the number of execution steps to predict
	MaxSteps int `yaml:"max_steps"`

	// Parallel enables parallel trace predictions
	Parallel bool `yaml:"parallel"`

	// MaxParallel limits concurrent predictions
	MaxParallel int `yaml:"max_parallel"`

	// IncludeVariables includes variable states in traces
	IncludeVariables bool `yaml:"include_variables"`

	// IncludeSideEffects tracks side effects in traces
	IncludeSideEffects bool `yaml:"include_side_effects"`
}

// SimilarityConfig configures cross-trace similarity metrics
type SimilarityConfig struct {
	// Metric specifies the similarity algorithm
	Metric string `yaml:"metric"` // "hybrid", "structural", "semantic"

	// StepAlignmentWeight is the weight for step alignment score
	StepAlignmentWeight float64 `yaml:"step_alignment_weight"`

	// StateMatchWeight is the weight for final state matching
	StateMatchWeight float64 `yaml:"state_match_weight"`

	// OutputMatchWeight is the weight for output matching
	OutputMatchWeight float64 `yaml:"output_match_weight"`

	// IgnoreOrdering ignores execution order differences
	IgnoreOrdering bool `yaml:"ignore_ordering"`
}

// ThresholdConfig configures decision thresholds
type ThresholdConfig struct {
	// DenyThreshold - scores below this trigger deny
	DenyThreshold float64 `yaml:"deny_threshold"`

	// AskThreshold - scores below this (but above deny) trigger ask
	AskThreshold float64 `yaml:"ask_threshold"`

	// Adaptive enables adaptive threshold adjustment
	Adaptive bool `yaml:"adaptive"`

	// TargetFPR is the target false positive rate for adaptive thresholds
	TargetFPR float64 `yaml:"target_fpr"`

	// MinSamples is minimum samples before adapting thresholds
	MinSamples int `yaml:"min_samples"`

	// AdaptationRate controls how fast thresholds adapt (0-1)
	AdaptationRate float64 `yaml:"adaptation_rate"`
}

// TriggerConfig defines when CTVP analysis is invoked
type TriggerConfig struct {
	// ToolNames is a list of regex patterns to match tool names
	ToolNames []string `yaml:"tool_names"`

	// MinCodeSize triggers for code above this size (bytes)
	MinCodeSize int `yaml:"min_code_size"`

	// Languages restricts analysis to these languages
	Languages []string `yaml:"languages,omitempty"`

	// Mode overrides the global mode for this trigger
	Mode Mode `yaml:"mode,omitempty"`
}

// BudgetConfig configures cost controls
type BudgetConfig struct {
	// Enabled controls whether budget tracking is active
	Enabled bool `yaml:"enabled"`

	// DailyLimitCents is the maximum daily spend in cents
	DailyLimitCents int `yaml:"daily_limit_cents"`

	// MaxCostPerAnalysis limits cost of a single analysis
	MaxCostPerAnalysis float64 `yaml:"max_cost_per_analysis"`

	// WarnAtPercent triggers a warning at this percentage of budget
	WarnAtPercent int `yaml:"warn_at_percent"`
}

// CacheConfig configures result caching
type CacheConfig struct {
	// Enabled controls whether caching is active
	Enabled bool `yaml:"enabled"`

	// MaxEntries is the maximum number of cached results
	MaxEntries int `yaml:"max_entries"`

	// TTL is the time-to-live for cached entries
	TTL time.Duration `yaml:"ttl"`
}

// DefaultConfig returns the default CTVP configuration
func DefaultConfig() *Config {
	return &Config{
		Enabled: false, // Experimental, off by default
		Mode:    ModeHybrid,
		Orbit: OrbitConfig{
			Size:    5,
			MinSize: 3,
			Transformations: []TransformationType{
				TransformVariableRename,
				TransformDeadCodeInjection,
				TransformStatementReorder,
				TransformReformat,
				TransformCommentModify,
			},
			MaxTransformAttempts: 3,
		},
		Trace: TraceConfig{
			MaxSteps:           20,
			Parallel:           true,
			MaxParallel:        3,
			IncludeVariables:   true,
			IncludeSideEffects: true,
		},
		Similarity: SimilarityConfig{
			Metric:              "hybrid",
			StepAlignmentWeight: 0.4,
			StateMatchWeight:    0.4,
			OutputMatchWeight:   0.2,
			IgnoreOrdering:      false,
		},
		Threshold: ThresholdConfig{
			DenyThreshold:  0.3,
			AskThreshold:   0.5,
			Adaptive:       true,
			TargetFPR:      0.05,
			MinSamples:     50,
			AdaptationRate: 0.1,
		},
		Triggers: []TriggerConfig{
			{
				ToolNames:   []string{"^Bash$"},
				MinCodeSize: 50,
			},
			{
				ToolNames:   []string{"^Write$"},
				MinCodeSize: 100,
			},
		},
		Budget: BudgetConfig{
			Enabled:            true,
			DailyLimitCents:    200,
			MaxCostPerAnalysis: 10.0,
			WarnAtPercent:      80,
		},
		Timeout: 30 * time.Second,
		Cache: CacheConfig{
			Enabled:    true,
			MaxEntries: 500,
			TTL:        15 * time.Minute,
		},
	}
}

// Validate validates the CTVP configuration
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

	// Validate orbit config
	if c.Orbit.Size < 2 {
		return &ConfigError{Field: "orbit.size", Message: "must be at least 2"}
	}
	if c.Orbit.MinSize < 2 {
		return &ConfigError{Field: "orbit.min_size", Message: "must be at least 2"}
	}
	if c.Orbit.MinSize > c.Orbit.Size {
		return &ConfigError{Field: "orbit.min_size", Message: "cannot exceed orbit.size"}
	}
	if len(c.Orbit.Transformations) == 0 {
		return &ConfigError{Field: "orbit.transformations", Message: "must have at least one transformation"}
	}

	// Validate trace config
	if c.Trace.MaxSteps < 1 {
		return &ConfigError{Field: "trace.max_steps", Message: "must be at least 1"}
	}
	if c.Trace.MaxParallel < 1 {
		return &ConfigError{Field: "trace.max_parallel", Message: "must be at least 1"}
	}

	// Validate similarity config
	switch c.Similarity.Metric {
	case "hybrid", "structural", "semantic":
		// Valid
	default:
		return &ConfigError{Field: "similarity.metric", Message: "must be 'hybrid', 'structural', or 'semantic'"}
	}

	// Validate weights sum to approximately 1
	weightSum := c.Similarity.StepAlignmentWeight + c.Similarity.StateMatchWeight + c.Similarity.OutputMatchWeight
	if weightSum < 0.99 || weightSum > 1.01 {
		return &ConfigError{Field: "similarity weights", Message: fmt.Sprintf("must sum to 1.0, got %.2f", weightSum)}
	}

	// Validate threshold config
	if c.Threshold.DenyThreshold < 0 || c.Threshold.DenyThreshold > 1 {
		return &ConfigError{Field: "threshold.deny_threshold", Message: "must be between 0 and 1"}
	}
	if c.Threshold.AskThreshold < 0 || c.Threshold.AskThreshold > 1 {
		return &ConfigError{Field: "threshold.ask_threshold", Message: "must be between 0 and 1"}
	}
	if c.Threshold.DenyThreshold > c.Threshold.AskThreshold {
		return &ConfigError{Field: "threshold", Message: "deny_threshold must be less than ask_threshold"}
	}
	if c.Threshold.TargetFPR < 0 || c.Threshold.TargetFPR > 1 {
		return &ConfigError{Field: "threshold.target_fpr", Message: "must be between 0 and 1"}
	}

	// Validate timeout
	if c.Timeout <= 0 {
		return &ConfigError{Field: "timeout", Message: "must be positive"}
	}

	return nil
}

// ConfigError represents a CTVP configuration error
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "ctvp config error: " + e.Field + ": " + e.Message
}
