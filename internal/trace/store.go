package trace

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"

	_ "modernc.org/sqlite" // SQLite driver for database/sql
)

// SessionStore defines the interface for session/event persistence
type SessionStore interface {
	// Session management
	GetOrCreateSession(sessionID, cwd, transcriptPath string) (*Session, error)
	UpdateSessionLastSeen(sessionID string) error
	GetSession(sessionID string) (*Session, error)
	DeleteSession(sessionID string) error
	ListSessions() ([]*Session, error)

	// Event management
	StoreEvent(event *Event) error
	GetSessionEvents(sessionID string, since time.Time) ([]*Event, error)
	GetEventByToolUseID(sessionID, toolUseID string) (*Event, error)
	GetRecentEvents(sessionID string, limit int) ([]*Event, error)

	// Cleanup
	CleanupOldSessions(ttl time.Duration) (int64, error)
	CleanupExcessEvents(sessionID string, maxEvents int) (int64, error)

	// Lifecycle
	Close() error
}

// SQLiteStore implements SessionStore using SQLite
type SQLiteStore struct {
	db     *sql.DB
	dbPath string
	mu     sync.RWMutex
}

// NewSQLiteStore creates a new SQLite-backed session store
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	if dbPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		dbPath = filepath.Join(homeDir, ".hooksy", "traces", "sessions.db")
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create trace directory: %w", err)
	}

	// Open database with WAL mode for better concurrency
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &SQLiteStore{
		db:     db,
		dbPath: dbPath,
	}

	if err := store.initSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	logger.Debug().
		Str("path", dbPath).
		Msg("Opened trace store")

	return store, nil
}

func (s *SQLiteStore) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS sessions (
		session_id TEXT PRIMARY KEY,
		created_at INTEGER NOT NULL,
		last_seen_at INTEGER NOT NULL,
		cwd TEXT,
		transcript_path TEXT
	);

	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		session_id TEXT NOT NULL,
		tool_use_id TEXT,
		event_type TEXT NOT NULL,
		tool_name TEXT,
		tool_input TEXT,
		tool_response TEXT,
		timestamp INTEGER NOT NULL,
		decision TEXT,
		rule_matched TEXT,
		FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_tool_use_id ON events(tool_use_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// GetOrCreateSession retrieves an existing session or creates a new one
func (s *SQLiteStore) GetOrCreateSession(sessionID, cwd, transcriptPath string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()

	// Try to get existing session
	session, err := s.getSessionLocked(sessionID)
	if err == nil {
		// Update last_seen_at
		_, err = s.db.Exec(
			"UPDATE sessions SET last_seen_at = ? WHERE session_id = ?",
			now, sessionID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to update session: %w", err)
		}
		session.LastSeenAt = time.Unix(now, 0)
		return session, nil
	}

	// Create new session
	_, err = s.db.Exec(
		`INSERT INTO sessions (session_id, created_at, last_seen_at, cwd, transcript_path)
		 VALUES (?, ?, ?, ?, ?)`,
		sessionID, now, now, cwd, transcriptPath,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	return &Session{
		SessionID:      sessionID,
		CreatedAt:      time.Unix(now, 0),
		LastSeenAt:     time.Unix(now, 0),
		Cwd:            cwd,
		TranscriptPath: transcriptPath,
	}, nil
}

// UpdateSessionLastSeen updates the last_seen_at timestamp
func (s *SQLiteStore) UpdateSessionLastSeen(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec(
		"UPDATE sessions SET last_seen_at = ? WHERE session_id = ?",
		time.Now().Unix(), sessionID,
	)
	if err != nil {
		return fmt.Errorf("failed to update session: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	return nil
}

// GetSession retrieves a session by ID
func (s *SQLiteStore) GetSession(sessionID string) (*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getSessionLocked(sessionID)
}

func (s *SQLiteStore) getSessionLocked(sessionID string) (*Session, error) {
	var session Session
	var createdAt, lastSeenAt int64

	err := s.db.QueryRow(
		`SELECT session_id, created_at, last_seen_at, cwd, transcript_path
		 FROM sessions WHERE session_id = ?`,
		sessionID,
	).Scan(&session.SessionID, &createdAt, &lastSeenAt, &session.Cwd, &session.TranscriptPath)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session not found: %s", sessionID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	session.CreatedAt = time.Unix(createdAt, 0)
	session.LastSeenAt = time.Unix(lastSeenAt, 0)
	return &session, nil
}

// DeleteSession removes a session and its events
func (s *SQLiteStore) DeleteSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Delete events first (foreign key)
	_, err = tx.Exec("DELETE FROM events WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete events: %w", err)
	}

	// Delete session
	_, err = tx.Exec("DELETE FROM sessions WHERE session_id = ?", sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return tx.Commit()
}

// ListSessions returns all sessions ordered by last_seen_at
func (s *SQLiteStore) ListSessions() ([]*Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT session_id, created_at, last_seen_at, cwd, transcript_path
		 FROM sessions ORDER BY last_seen_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var sessions []*Session
	for rows.Next() {
		var session Session
		var createdAt, lastSeenAt int64

		if err := rows.Scan(&session.SessionID, &createdAt, &lastSeenAt, &session.Cwd, &session.TranscriptPath); err != nil {
			return nil, fmt.Errorf("failed to scan session: %w", err)
		}

		session.CreatedAt = time.Unix(createdAt, 0)
		session.LastSeenAt = time.Unix(lastSeenAt, 0)
		sessions = append(sessions, &session)
	}

	return sessions, rows.Err()
}

// StoreEvent stores a new event in the database
func (s *SQLiteStore) StoreEvent(event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var toolInputJSON, toolResponseJSON []byte
	var err error

	if event.ToolInput != nil {
		toolInputJSON, err = json.Marshal(event.ToolInput)
		if err != nil {
			return fmt.Errorf("failed to marshal tool_input: %w", err)
		}
	}

	if event.ToolResponse != nil {
		toolResponseJSON, err = json.Marshal(event.ToolResponse)
		if err != nil {
			return fmt.Errorf("failed to marshal tool_response: %w", err)
		}
	}

	result, err := s.db.Exec(
		`INSERT INTO events (session_id, tool_use_id, event_type, tool_name, tool_input, tool_response, timestamp, decision, rule_matched)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.SessionID,
		event.ToolUseID,
		string(event.EventType),
		event.ToolName,
		string(toolInputJSON),
		string(toolResponseJSON),
		event.Timestamp.Unix(),
		event.Decision,
		event.RuleMatched,
	)
	if err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	id, err := result.LastInsertId()
	if err == nil {
		event.ID = id
	}

	return nil
}

// GetSessionEvents retrieves events for a session since a given time
func (s *SQLiteStore) GetSessionEvents(sessionID string, since time.Time) ([]*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, session_id, tool_use_id, event_type, tool_name, tool_input, tool_response, timestamp, decision, rule_matched
		 FROM events
		 WHERE session_id = ? AND timestamp >= ?
		 ORDER BY timestamp ASC`,
		sessionID, since.Unix(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	return s.scanEvents(rows)
}

// GetEventByToolUseID finds an event by its tool_use_id within a session
func (s *SQLiteStore) GetEventByToolUseID(sessionID, toolUseID string) (*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var event Event
	var timestamp int64
	var toolInputJSON, toolResponseJSON sql.NullString
	var toolUseIDNull, toolName, decision, ruleMatched sql.NullString

	err := s.db.QueryRow(
		`SELECT id, session_id, tool_use_id, event_type, tool_name, tool_input, tool_response, timestamp, decision, rule_matched
		 FROM events
		 WHERE session_id = ? AND tool_use_id = ?
		 ORDER BY timestamp ASC
		 LIMIT 1`,
		sessionID, toolUseID,
	).Scan(&event.ID, &event.SessionID, &toolUseIDNull, &event.EventType, &toolName, &toolInputJSON, &toolResponseJSON, &timestamp, &decision, &ruleMatched)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("event not found with tool_use_id: %s", toolUseID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get event: %w", err)
	}

	event.ToolUseID = toolUseIDNull.String
	event.ToolName = toolName.String
	event.Decision = decision.String
	event.RuleMatched = ruleMatched.String
	event.Timestamp = time.Unix(timestamp, 0)

	if toolInputJSON.Valid && toolInputJSON.String != "" {
		if err := json.Unmarshal([]byte(toolInputJSON.String), &event.ToolInput); err != nil {
			logger.Debug().Err(err).Msg("Failed to unmarshal tool_input")
		}
	}

	if toolResponseJSON.Valid && toolResponseJSON.String != "" {
		if err := json.Unmarshal([]byte(toolResponseJSON.String), &event.ToolResponse); err != nil {
			logger.Debug().Err(err).Msg("Failed to unmarshal tool_response")
		}
	}

	return &event, nil
}

// GetRecentEvents retrieves the most recent events for a session
func (s *SQLiteStore) GetRecentEvents(sessionID string, limit int) ([]*Event, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, session_id, tool_use_id, event_type, tool_name, tool_input, tool_response, timestamp, decision, rule_matched
		 FROM events
		 WHERE session_id = ?
		 ORDER BY timestamp DESC
		 LIMIT ?`,
		sessionID, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get recent events: %w", err)
	}
	defer func() { _ = rows.Close() }()

	events, err := s.scanEvents(rows)
	if err != nil {
		return nil, err
	}

	// Reverse to get chronological order
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	return events, nil
}

func (s *SQLiteStore) scanEvents(rows *sql.Rows) ([]*Event, error) {
	var events []*Event

	for rows.Next() {
		var event Event
		var timestamp int64
		var toolInputJSON, toolResponseJSON sql.NullString
		var toolUseID, toolName, decision, ruleMatched sql.NullString
		var eventType string

		if err := rows.Scan(&event.ID, &event.SessionID, &toolUseID, &eventType, &toolName, &toolInputJSON, &toolResponseJSON, &timestamp, &decision, &ruleMatched); err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}

		event.EventType = hooks.EventType(eventType)
		event.ToolUseID = toolUseID.String
		event.ToolName = toolName.String
		event.Decision = decision.String
		event.RuleMatched = ruleMatched.String
		event.Timestamp = time.Unix(timestamp, 0)

		if toolInputJSON.Valid && toolInputJSON.String != "" {
			if err := json.Unmarshal([]byte(toolInputJSON.String), &event.ToolInput); err != nil {
				logger.Debug().Err(err).Msg("Failed to unmarshal tool_input")
			}
		}

		if toolResponseJSON.Valid && toolResponseJSON.String != "" {
			if err := json.Unmarshal([]byte(toolResponseJSON.String), &event.ToolResponse); err != nil {
				logger.Debug().Err(err).Msg("Failed to unmarshal tool_response")
			}
		}

		events = append(events, &event)
	}

	return events, rows.Err()
}

// CleanupOldSessions removes sessions older than the given TTL
func (s *SQLiteStore) CleanupOldSessions(ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-ttl).Unix()

	// Delete events for old sessions
	_, err := s.db.Exec("DELETE FROM events WHERE session_id IN (SELECT session_id FROM sessions WHERE last_seen_at < ?)", cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old events: %w", err)
	}

	// Delete old sessions
	result, err := s.db.Exec("DELETE FROM sessions WHERE last_seen_at < ?", cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old sessions: %w", err)
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		logger.Debug().
			Int64("deleted", deleted).
			Str("ttl", ttl.String()).
			Msg("Cleaned up old sessions")
	}

	return deleted, nil
}

// CleanupExcessEvents removes oldest events when session exceeds max events
func (s *SQLiteStore) CleanupExcessEvents(sessionID string, maxEvents int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Count current events
	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM events WHERE session_id = ?", sessionID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count events: %w", err)
	}

	if count <= maxEvents {
		return 0, nil
	}

	// Delete oldest events exceeding the limit
	toDelete := count - maxEvents
	result, err := s.db.Exec(
		`DELETE FROM events WHERE id IN (
			SELECT id FROM events WHERE session_id = ? ORDER BY timestamp ASC LIMIT ?
		)`,
		sessionID, toDelete,
	)
	if err != nil {
		return 0, fmt.Errorf("failed to delete excess events: %w", err)
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		logger.Debug().
			Int64("deleted", deleted).
			Str("session", sessionID).
			Msg("Cleaned up excess events")
	}

	return deleted, nil
}

// Close closes the database connection
func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// MaybeRunCleanup runs cleanup with the given probability
func MaybeRunCleanup(store SessionStore, settings config.TraceSettings) {
	if rand.Float64() > settings.CleanupProbability {
		return
	}

	ttl, err := time.ParseDuration(settings.SessionTTL)
	if err != nil {
		ttl = 24 * time.Hour
	}

	go func() {
		_, err := store.CleanupOldSessions(ttl)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to cleanup old sessions")
		}
	}()
}
