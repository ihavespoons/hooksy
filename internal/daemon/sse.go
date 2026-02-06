package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/ihavespoons/hooksy/internal/trace"
)

// SSEBroadcaster manages SSE connections and broadcasts events
type SSEBroadcaster struct {
	clients      map[chan SSEEvent]bool
	mu           sync.RWMutex
	store        trace.SessionStore
	lastEventID  int64
	pollInterval time.Duration
	stopCh       chan struct{}
	wg           sync.WaitGroup
}

// NewSSEBroadcaster creates a new SSE broadcaster
func NewSSEBroadcaster(store trace.SessionStore) *SSEBroadcaster {
	return &SSEBroadcaster{
		clients:      make(map[chan SSEEvent]bool),
		store:        store,
		pollInterval: 500 * time.Millisecond,
		stopCh:       make(chan struct{}),
	}
}

// Start begins polling for new events
func (b *SSEBroadcaster) Start(ctx context.Context) {
	b.wg.Add(2)

	// Polling goroutine
	go func() {
		defer b.wg.Done()
		b.pollForEvents(ctx)
	}()

	// Heartbeat goroutine
	go func() {
		defer b.wg.Done()
		b.sendHeartbeats(ctx)
	}()
}

// Stop stops the broadcaster
func (b *SSEBroadcaster) Stop() {
	close(b.stopCh)
	b.wg.Wait()

	// Close all client channels
	b.mu.Lock()
	for ch := range b.clients {
		close(ch)
		delete(b.clients, ch)
	}
	b.mu.Unlock()
}

// Subscribe adds a new client to receive events
func (b *SSEBroadcaster) Subscribe() chan SSEEvent {
	ch := make(chan SSEEvent, 100)
	b.mu.Lock()
	b.clients[ch] = true
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a client
func (b *SSEBroadcaster) Unsubscribe(ch chan SSEEvent) {
	b.mu.Lock()
	if _, ok := b.clients[ch]; ok {
		delete(b.clients, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// Broadcast sends an event to all connected clients
func (b *SSEBroadcaster) Broadcast(event SSEEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for ch := range b.clients {
		select {
		case ch <- event:
		default:
			// Channel is full, skip this client
			logger.Debug().Msg("SSE client channel full, dropping event")
		}
	}
}

// ClientCount returns the number of connected clients
func (b *SSEBroadcaster) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

func (b *SSEBroadcaster) pollForEvents(ctx context.Context) {
	ticker := time.NewTicker(b.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.checkForNewEvents()
		}
	}
}

func (b *SSEBroadcaster) checkForNewEvents() {
	if b.store == nil {
		return
	}

	// Get all sessions
	sessions, err := b.store.ListSessions()
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to list sessions for SSE polling")
		return
	}

	// Check for new events in each session
	for _, session := range sessions {
		events, err := b.store.GetRecentEvents(session.SessionID, 100)
		if err != nil {
			continue
		}

		for _, event := range events {
			if event.ID > b.lastEventID {
				b.lastEventID = event.ID

				// Broadcast new event
				b.Broadcast(SSEEvent{
					Type: SSEEventNew,
					Data: EventResponse{
						ID:          event.ID,
						SessionID:   event.SessionID,
						ToolUseID:   event.ToolUseID,
						EventType:   event.EventType,
						ToolName:    event.ToolName,
						ToolInput:   event.ToolInput,
						Timestamp:   event.Timestamp,
						Decision:    event.Decision,
						RuleMatched: event.RuleMatched,
					},
				})

				// If a rule was matched, also send a rule_match event
				if event.RuleMatched != "" {
					b.Broadcast(SSEEvent{
						Type: SSERuleMatch,
						Data: map[string]any{
							"rule_name":  event.RuleMatched,
							"decision":   event.Decision,
							"event_id":   event.ID,
							"session_id": event.SessionID,
						},
					})
				}
			}
		}
	}
}

func (b *SSEBroadcaster) sendHeartbeats(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stopCh:
			return
		case <-ticker.C:
			b.Broadcast(SSEEvent{
				Type: SSEHeartbeat,
				Data: map[string]any{
					"time":    time.Now().UTC(),
					"clients": b.ClientCount(),
				},
			})
		}
	}
}

// ServeHTTP handles SSE connections
func (b *SSEBroadcaster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Get the flusher
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Subscribe to events
	ch := b.Subscribe()
	defer b.Unsubscribe(ch)

	// Send initial connection event
	writeSSEEvent(w, SSEEvent{
		Type: "connected",
		Data: map[string]any{
			"message": "Connected to hooksy dashboard",
			"time":    time.Now().UTC(),
		},
	})
	flusher.Flush()

	// Listen for events
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-ch:
			if !ok {
				return
			}
			writeSSEEvent(w, event)
			flusher.Flush()
		}
	}
}

func writeSSEEvent(w http.ResponseWriter, event SSEEvent) {
	data, err := json.Marshal(event.Data)
	if err != nil {
		return
	}

	_, _ = fmt.Fprintf(w, "event: %s\n", event.Type)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", data)
}
