package config

import "github.com/ihavespoons/hooksy/internal/hooks"

// Config represents the complete hooksy configuration
type Config struct {
	Version   string   `yaml:"version"`
	Settings  Settings `yaml:"settings"`
	Rules     Rules    `yaml:"rules"`
	Allowlist []Rule   `yaml:"allowlist,omitempty"`
}

// Settings contains global configuration settings
type Settings struct {
	LogLevel        string `yaml:"log_level"`
	LogFile         string `yaml:"log_file,omitempty"`
	DefaultDecision string `yaml:"default_decision"`
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
		},
		Rules: Rules{},
	}
}
