package trace

import (
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
)

// Session represents a Claude Code session for trace analysis
type Session struct {
	SessionID      string
	CreatedAt      time.Time
	LastSeenAt     time.Time
	Cwd            string
	TranscriptPath string
}

// Event represents a single traced event within a session
type Event struct {
	ID           int64
	SessionID    string
	ToolUseID    string // Correlates PreToolUse <-> PostToolUse
	EventType    hooks.EventType
	ToolName     string
	ToolInput    map[string]interface{}
	ToolResponse map[string]interface{}
	Timestamp    time.Time
	Decision     string
	RuleMatched  string
}

// PatternMatch represents a matched pattern in sequence analysis
type PatternMatch struct {
	RuleName    string
	Description string
	Severity    string // critical, warning, info
	Decision    string
	Message     string
	Events      []*Event // Events that matched the pattern
	Window      time.Duration
}

// SessionRulesSnapshot stores a snapshot of rules for a session
type SessionRulesSnapshot struct {
	ID            int64
	SessionID     string
	Rules         *config.Rules
	SequenceRules []config.SequenceRule
	RulesHash     string
	CreatedAt     time.Time
}
