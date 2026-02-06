package daemon

import (
	"time"

	"github.com/ihavespoons/hooksy/internal/hooks"
)

// SessionResponse represents a session in API responses
type SessionResponse struct {
	SessionID      string    `json:"session_id"`
	CreatedAt      time.Time `json:"created_at"`
	LastSeenAt     time.Time `json:"last_seen_at"`
	Cwd            string    `json:"cwd,omitempty"`
	TranscriptPath string    `json:"transcript_path,omitempty"`
	EventCount     int       `json:"event_count"`
}

// EventResponse represents an event in API responses
type EventResponse struct {
	ID          int64                  `json:"id"`
	SessionID   string                 `json:"session_id"`
	ToolUseID   string                 `json:"tool_use_id,omitempty"`
	EventType   hooks.EventType        `json:"event_type"`
	ToolName    string                 `json:"tool_name,omitempty"`
	ToolInput   map[string]any `json:"tool_input,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Decision    string                 `json:"decision,omitempty"`
	RuleMatched string                 `json:"rule_matched,omitempty"`
}

// EventDetailResponse represents a full event with tool_response
type EventDetailResponse struct {
	ID           int64                  `json:"id"`
	SessionID    string                 `json:"session_id"`
	ToolUseID    string                 `json:"tool_use_id,omitempty"`
	EventType    hooks.EventType        `json:"event_type"`
	ToolName     string                 `json:"tool_name,omitempty"`
	ToolInput    map[string]any `json:"tool_input,omitempty"`
	ToolResponse map[string]any `json:"tool_response,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
	Decision     string                 `json:"decision,omitempty"`
	RuleMatched  string                 `json:"rule_matched,omitempty"`
}

// RuleResponse represents a rule in API responses
type RuleResponse struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	EventType   string `json:"event_type"`
	Decision    string `json:"decision"`
	MatchCount  int    `json:"match_count"`
}

// StatsResponse represents aggregate statistics
type StatsResponse struct {
	TotalSessions   int            `json:"total_sessions"`
	ActiveSessions  int            `json:"active_sessions"`
	TotalEvents     int            `json:"total_events"`
	Events24h       int            `json:"events_24h"`
	Violations      int            `json:"violations"`
	Violations24h   int            `json:"violations_24h"`
	EventsByType    map[string]int `json:"events_by_type"`
	DecisionCounts  map[string]int `json:"decision_counts"`
	TopRulesMatched []RuleMatch    `json:"top_rules_matched"`
}

// RuleMatch represents a rule and its match count
type RuleMatch struct {
	RuleName   string `json:"rule_name"`
	MatchCount int    `json:"match_count"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status    string    `json:"status"`
	Version   string    `json:"version"`
	Uptime    string    `json:"uptime"`
	StartedAt time.Time `json:"started_at"`
}

// SSEEvent represents a server-sent event
type SSEEvent struct {
	Type string      `json:"type"`
	Data any `json:"data"`
}

// SSE event types
const (
	SSEEventNew       = "event_new"
	SSERuleMatch      = "rule_match"
	SSESessionUpdate  = "session_update"
	SSEStatsUpdate    = "stats_update"
	SSEHeartbeat      = "heartbeat"
)
