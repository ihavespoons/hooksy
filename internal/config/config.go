package config

import "github.com/ihavespoons/hooksy/internal/hooks"

// Config represents the complete hooksy configuration
type Config struct {
	Version       string         `yaml:"version"`
	Settings      Settings       `yaml:"settings"`
	Rules         Rules          `yaml:"rules"`
	Allowlist     []Rule         `yaml:"allowlist,omitempty"`
	SequenceRules []SequenceRule `yaml:"sequence_rules,omitempty"`
}

// Settings contains global configuration settings
type Settings struct {
	LogLevel        string        `yaml:"log_level"`
	LogFile         string        `yaml:"log_file,omitempty"`
	DefaultDecision string        `yaml:"default_decision"`
	Trace           TraceSettings `yaml:"trace,omitempty"`
}

// TraceSettings configures the trace analysis feature
type TraceSettings struct {
	Enabled             bool    `yaml:"enabled"`
	StoragePath         string  `yaml:"storage_path,omitempty"`
	SessionTTL          string  `yaml:"session_ttl,omitempty"`
	MaxEventsPerSession int     `yaml:"max_events_per_session,omitempty"`
	CleanupProbability  float64 `yaml:"cleanup_probability,omitempty"`
}

// DefaultTraceSettings returns the default trace settings
func DefaultTraceSettings() TraceSettings {
	return TraceSettings{
		Enabled:             false,
		StoragePath:         "",
		SessionTTL:          "24h",
		MaxEventsPerSession: 1000,
		CleanupProbability:  0.1,
	}
}

// SequenceRule defines a multi-event pattern to detect
type SequenceRule struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description,omitempty"`
	Enabled     bool            `yaml:"enabled"`
	Severity    string          `yaml:"severity,omitempty"`
	Window      string          `yaml:"window,omitempty"`
	Events      []SequenceEvent `yaml:"events"`
	Decision    string          `yaml:"decision"`
	Message     string          `yaml:"message,omitempty"`
}

// SequenceEvent defines a single event in a sequence pattern
type SequenceEvent struct {
	EventType        hooks.EventType   `yaml:"event_type"`
	ToolName         string            `yaml:"tool_name,omitempty"`
	ToolInput        map[string]string `yaml:"tool_input,omitempty"`
	Label            string            `yaml:"label,omitempty"`
	After            string            `yaml:"after,omitempty"`
	Count            string            `yaml:"count,omitempty"`
	ToolUseIDMatches string            `yaml:"tool_use_id_matches,omitempty"`
	IntentCheck      *IntentCheck      `yaml:"intent_check,omitempty"`
}

// IntentCheck configures intent vs action comparison
type IntentCheck struct {
	Enabled bool `yaml:"enabled"`
}

// Rules contains rules organized by hook event type
type Rules struct {
	PreToolUse       []Rule `yaml:"PreToolUse,omitempty"`
	PostToolUse      []Rule `yaml:"PostToolUse,omitempty"`
	UserPromptSubmit []Rule `yaml:"UserPromptSubmit,omitempty"`
	Stop             []Rule `yaml:"Stop,omitempty"`
	SubagentStop     []Rule `yaml:"SubagentStop,omitempty"`
	Notification     []Rule `yaml:"Notification,omitempty"`
	SessionStart     []Rule `yaml:"SessionStart,omitempty"`
	SessionEnd       []Rule `yaml:"SessionEnd,omitempty"`
}

// GetRulesForEvent returns the rules for a specific event type
func (r *Rules) GetRulesForEvent(event hooks.EventType) []Rule {
	switch event {
	case hooks.PreToolUse:
		return r.PreToolUse
	case hooks.PostToolUse:
		return r.PostToolUse
	case hooks.UserPromptSubmit:
		return r.UserPromptSubmit
	case hooks.Stop:
		return r.Stop
	case hooks.SubagentStop:
		return r.SubagentStop
	case hooks.Notification:
		return r.Notification
	case hooks.SessionStart:
		return r.SessionStart
	case hooks.SessionEnd:
		return r.SessionEnd
	default:
		return nil
	}
}

// Rule represents a single security rule
type Rule struct {
	Name          string         `yaml:"name"`
	Description   string         `yaml:"description,omitempty"`
	Enabled       bool           `yaml:"enabled"`
	Priority      int            `yaml:"priority,omitempty"`
	Conditions    Conditions     `yaml:"conditions"`
	Decision      string         `yaml:"decision"`
	Action        string         `yaml:"action,omitempty"`
	Modifications *Modifications `yaml:"modifications,omitempty"`
	SystemMessage string         `yaml:"system_message,omitempty"`
}

// Conditions represents the matching conditions for a rule
type Conditions struct {
	ToolName     string                    `yaml:"tool_name,omitempty"`
	ToolInput    map[string][]PatternMatch `yaml:"tool_input,omitempty"`
	ToolResponse []PatternMatch            `yaml:"tool_response,omitempty"`
	Prompt       []PatternMatch            `yaml:"prompt,omitempty"`
}

// PatternMatch represents a regex pattern with an associated message
type PatternMatch struct {
	Pattern string `yaml:"pattern"`
	Message string `yaml:"message,omitempty"`
}

// Modifications represents changes to make to tool input
type Modifications struct {
	ToolInput map[string]ModifyAction `yaml:"tool_input,omitempty"`
}

// ModifyAction represents how to modify a field
type ModifyAction struct {
	Append  string `yaml:"append,omitempty"`
	Prepend string `yaml:"prepend,omitempty"`
	Replace string `yaml:"replace,omitempty"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Settings: Settings{
			LogLevel:        "info",
			DefaultDecision: "allow",
			Trace:           DefaultTraceSettings(),
		},
		Rules: Rules{},
	}
}
