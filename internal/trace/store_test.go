package trace

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
)

func TestNewSQLiteStore(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Verify database file was created
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}
}

func TestNewSQLiteStoreDefaultPath(t *testing.T) {
	// Test that empty path uses default
	store, err := NewSQLiteStore("")
	if err != nil {
		t.Fatalf("Failed to create store with default path: %v", err)
	}
	defer store.Close()

	homeDir, _ := os.UserHomeDir()
	expectedDir := filepath.Join(homeDir, ".hooksy", "traces")
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Error("Default trace directory was not created")
	}
}

func TestSessionCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Create session
	session, err := store.GetOrCreateSession("test-session-1", "/home/user/project", "/tmp/transcript.jsonl")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	if session.SessionID != "test-session-1" {
		t.Errorf("Expected session ID 'test-session-1', got '%s'", session.SessionID)
	}
	if session.Cwd != "/home/user/project" {
		t.Errorf("Expected cwd '/home/user/project', got '%s'", session.Cwd)
	}

	// Get existing session
	session2, err := store.GetOrCreateSession("test-session-1", "/home/user/project", "/tmp/transcript.jsonl")
	if err != nil {
		t.Fatalf("Failed to get existing session: %v", err)
	}

	if session2.SessionID != session.SessionID {
		t.Error("Expected to get same session")
	}

	// Get session by ID
	session3, err := store.GetSession("test-session-1")
	if err != nil {
		t.Fatalf("Failed to get session: %v", err)
	}

	if session3.SessionID != "test-session-1" {
		t.Error("GetSession returned wrong session")
	}

	// List sessions
	sessions, err := store.ListSessions()
	if err != nil {
		t.Fatalf("Failed to list sessions: %v", err)
	}

	if len(sessions) != 1 {
		t.Errorf("Expected 1 session, got %d", len(sessions))
	}

	// Delete session
	err = store.DeleteSession("test-session-1")
	if err != nil {
		t.Fatalf("Failed to delete session: %v", err)
	}

	// Verify session is deleted
	_, err = store.GetSession("test-session-1")
	if err == nil {
		t.Error("Expected error getting deleted session")
	}
}

func TestEventCRUD(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Create session first
	_, err = store.GetOrCreateSession("test-session-1", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Store event
	event := &Event{
		SessionID: "test-session-1",
		ToolUseID: "tool-123",
		EventType: hooks.PreToolUse,
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{
			"command": "ls -la",
		},
		Timestamp:   time.Now(),
		Decision:    "allow",
		RuleMatched: "",
	}

	err = store.StoreEvent(event)
	if err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	if event.ID == 0 {
		t.Error("Event ID was not set after store")
	}

	// Get event by tool_use_id
	retrieved, err := store.GetEventByToolUseID("test-session-1", "tool-123")
	if err != nil {
		t.Fatalf("Failed to get event by tool_use_id: %v", err)
	}

	if retrieved.ToolName != "Bash" {
		t.Errorf("Expected tool name 'Bash', got '%s'", retrieved.ToolName)
	}

	if retrieved.ToolInput["command"] != "ls -la" {
		t.Error("Tool input not preserved correctly")
	}

	// Get recent events
	events, err := store.GetRecentEvents("test-session-1", 10)
	if err != nil {
		t.Fatalf("Failed to get recent events: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}
}

func TestGetSessionEvents(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	_, err = store.GetOrCreateSession("test-session-1", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	baseTime := time.Now().Add(-10 * time.Minute)

	// Store multiple events
	for i := range 5 {
		event := &Event{
			SessionID: "test-session-1",
			ToolUseID: "",
			EventType: hooks.PreToolUse,
			ToolName:  "Bash",
			ToolInput: map[string]interface{}{
				"command": "echo test",
			},
			Timestamp: baseTime.Add(time.Duration(i) * time.Minute),
		}
		if err := store.StoreEvent(event); err != nil {
			t.Fatalf("Failed to store event %d: %v", i, err)
		}
	}

	// Get events since 5 minutes ago
	since := baseTime.Add(2 * time.Minute)
	events, err := store.GetSessionEvents("test-session-1", since)
	if err != nil {
		t.Fatalf("Failed to get session events: %v", err)
	}

	// Should get events at index 2, 3, 4 (3 events)
	if len(events) != 3 {
		t.Errorf("Expected 3 events since %v, got %d", since, len(events))
	}
}

func TestToolUseIDCorrelation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	_, err = store.GetOrCreateSession("test-session-1", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Store PreToolUse event
	preEvent := &Event{
		SessionID: "test-session-1",
		ToolUseID: "correlated-tool-123",
		EventType: hooks.PreToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/etc/passwd",
		},
		Timestamp: time.Now(),
		Decision:  "allow",
	}
	if err := store.StoreEvent(preEvent); err != nil {
		t.Fatalf("Failed to store PreToolUse event: %v", err)
	}

	// Store PostToolUse event with same tool_use_id
	postEvent := &Event{
		SessionID: "test-session-1",
		ToolUseID: "correlated-tool-123",
		EventType: hooks.PostToolUse,
		ToolName:  "Read",
		ToolInput: map[string]interface{}{
			"file_path": "/etc/passwd",
		},
		ToolResponse: map[string]interface{}{
			"content": "root:x:0:0:root:/root:/bin/bash",
		},
		Timestamp: time.Now().Add(time.Second),
	}
	if err := store.StoreEvent(postEvent); err != nil {
		t.Fatalf("Failed to store PostToolUse event: %v", err)
	}

	// Get the PreToolUse event by tool_use_id
	retrieved, err := store.GetEventByToolUseID("test-session-1", "correlated-tool-123")
	if err != nil {
		t.Fatalf("Failed to get event by tool_use_id: %v", err)
	}

	// Should get the first (PreToolUse) event
	if retrieved.EventType != hooks.PreToolUse {
		t.Errorf("Expected PreToolUse event, got %s", retrieved.EventType)
	}
}

func TestCleanupOldSessions(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	// Create session and update last_seen to be old
	_, err = store.GetOrCreateSession("old-session", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Manually set the last_seen_at to be old
	oldTime := time.Now().Add(-48 * time.Hour).Unix()
	_, err = store.db.Exec("UPDATE sessions SET last_seen_at = ? WHERE session_id = ?", oldTime, "old-session")
	if err != nil {
		t.Fatalf("Failed to update session timestamp: %v", err)
	}

	// Create a recent session
	_, err = store.GetOrCreateSession("new-session", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Cleanup sessions older than 24 hours
	deleted, err := store.CleanupOldSessions(24 * time.Hour)
	if err != nil {
		t.Fatalf("Failed to cleanup old sessions: %v", err)
	}

	if deleted != 1 {
		t.Errorf("Expected 1 deleted session, got %d", deleted)
	}

	// Verify old session is gone but new session exists
	_, err = store.GetSession("old-session")
	if err == nil {
		t.Error("Old session should have been deleted")
	}

	_, err = store.GetSession("new-session")
	if err != nil {
		t.Error("New session should still exist")
	}
}

func TestCleanupExcessEvents(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	_, err = store.GetOrCreateSession("test-session-1", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Store 10 events
	for i := range 10 {
		event := &Event{
			SessionID: "test-session-1",
			EventType: hooks.PreToolUse,
			ToolName:  "Bash",
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
		}
		if err := store.StoreEvent(event); err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}
	}

	// Cleanup to keep only 5 events
	deleted, err := store.CleanupExcessEvents("test-session-1", 5)
	if err != nil {
		t.Fatalf("Failed to cleanup excess events: %v", err)
	}

	if deleted != 5 {
		t.Errorf("Expected 5 deleted events, got %d", deleted)
	}

	// Verify only 5 events remain
	events, err := store.GetRecentEvents("test-session-1", 100)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 5 {
		t.Errorf("Expected 5 events remaining, got %d", len(events))
	}
}

func TestMaybeRunCleanup(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	settings := config.TraceSettings{
		Enabled:            true,
		SessionTTL:         "1h",
		CleanupProbability: 1.0, // Always run
	}

	// This should not panic
	MaybeRunCleanup(store, settings)

	// Give goroutine time to run
	time.Sleep(100 * time.Millisecond)
}

func TestConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	_, err = store.GetOrCreateSession("test-session-1", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Concurrent writes
	done := make(chan bool)
	for i := range 10 {
		go func(idx int) {
			event := &Event{
				SessionID: "test-session-1",
				EventType: hooks.PreToolUse,
				ToolName:  "Bash",
				Timestamp: time.Now(),
			}
			if err := store.StoreEvent(event); err != nil {
				t.Errorf("Concurrent write %d failed: %v", idx, err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}

	// Verify all events were stored
	events, err := store.GetRecentEvents("test-session-1", 100)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 10 {
		t.Errorf("Expected 10 events, got %d", len(events))
	}
}

func TestEventWithNullFields(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}
	defer store.Close()

	_, err = store.GetOrCreateSession("test-session-1", "/home/user/project", "")
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Store event with nil maps
	event := &Event{
		SessionID:    "test-session-1",
		EventType:    hooks.UserPromptSubmit,
		Timestamp:    time.Now(),
		ToolInput:    nil,
		ToolResponse: nil,
	}

	err = store.StoreEvent(event)
	if err != nil {
		t.Fatalf("Failed to store event with null fields: %v", err)
	}

	// Retrieve it
	events, err := store.GetRecentEvents("test-session-1", 1)
	if err != nil {
		t.Fatalf("Failed to get events: %v", err)
	}

	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}

	if events[0].ToolInput != nil {
		t.Error("Expected nil ToolInput")
	}
}
