package daemon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/trace"
)

// Handlers contains the HTTP handlers for the daemon API
type Handlers struct {
	store     trace.SessionStore
	cfg       *config.Config
	startedAt time.Time
	version   string
}

// NewHandlers creates a new handlers instance
func NewHandlers(store trace.SessionStore, cfg *config.Config, version string) *Handlers {
	return &Handlers{
		store:     store,
		cfg:       cfg,
		startedAt: time.Now(),
		version:   version,
	}
}

// Health handles the health check endpoint
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	resp := HealthResponse{
		Status:    "ok",
		Version:   h.version,
		Uptime:    time.Since(h.startedAt).Round(time.Second).String(),
		StartedAt: h.startedAt,
	}
	writeJSON(w, http.StatusOK, resp)
}

// Sessions handles the sessions list endpoint
func (h *Handlers) Sessions(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, []SessionResponse{})
		return
	}

	sessions, err := h.store.ListSessions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]SessionResponse, 0, len(sessions))
	for _, s := range sessions {
		events, _ := h.store.GetRecentEvents(s.SessionID, 10000)
		resp = append(resp, SessionResponse{
			SessionID:      s.SessionID,
			CreatedAt:      s.CreatedAt,
			LastSeenAt:     s.LastSeenAt,
			Cwd:            s.Cwd,
			TranscriptPath: s.TranscriptPath,
			EventCount:     len(events),
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

// Events handles the events list endpoint
func (h *Handlers) Events(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, []EventResponse{})
		return
	}

	// Parse query parameters
	sessionID := r.URL.Query().Get("session_id")
	limitStr := r.URL.Query().Get("limit")
	sinceStr := r.URL.Query().Get("since")
	eventType := r.URL.Query().Get("event_type")
	decision := r.URL.Query().Get("decision")
	toolName := r.URL.Query().Get("tool_name")
	sortOrder := r.URL.Query().Get("sort") // "asc" or "desc", default "desc"

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	var since time.Time
	if sinceStr != "" {
		if t, err := time.Parse(time.RFC3339, sinceStr); err == nil {
			since = t
		}
	}

	if sortOrder == "" {
		sortOrder = "desc"
	}

	// Use filtered events query
	opts := trace.EventFilterOptions{
		SessionID: sessionID,
		EventType: eventType,
		Decision:  decision,
		ToolName:  toolName,
		SortOrder: sortOrder,
		Limit:     limit,
		Since:     since,
	}

	allEvents, err := h.store.GetFilteredEvents(opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := make([]EventResponse, 0, len(allEvents))
	for _, e := range allEvents {
		resp = append(resp, EventResponse{
			ID:          e.ID,
			SessionID:   e.SessionID,
			ToolUseID:   e.ToolUseID,
			EventType:   e.EventType,
			ToolName:    e.ToolName,
			ToolInput:   e.ToolInput,
			Timestamp:   e.Timestamp,
			Decision:    e.Decision,
			RuleMatched: e.RuleMatched,
		})
	}

	writeJSON(w, http.StatusOK, resp)
}

// Rules handles the active rules endpoint
func (h *Handlers) Rules(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session_id")

	// If session_id is provided, try to get session-specific rules
	if sessionID != "" && h.store != nil {
		snapshot, err := h.store.GetSessionRules(sessionID)
		if err == nil && snapshot != nil {
			resp := h.buildRulesResponse(snapshot.Rules, snapshot.SequenceRules)
			writeJSON(w, http.StatusOK, resp)
			return
		}
	}

	// Fall back to daemon's current config rules
	if h.cfg == nil {
		writeJSON(w, http.StatusOK, []RuleResponse{})
		return
	}

	resp := h.buildRulesResponse(&h.cfg.Rules, h.cfg.SequenceRules)
	writeJSON(w, http.StatusOK, resp)
}

// buildRulesResponse converts rules to response format
func (h *Handlers) buildRulesResponse(rules *config.Rules, sequenceRules []config.SequenceRule) []RuleResponse {
	resp := []RuleResponse{}

	if rules == nil {
		return resp
	}

	// Collect rules from all event types
	addRules := func(ruleList []config.Rule, eventType string) {
		for _, rule := range ruleList {
			resp = append(resp, RuleResponse{
				Name:        rule.Name,
				Description: rule.Description,
				Enabled:     rule.Enabled,
				EventType:   eventType,
				Decision:    rule.Decision,
				MatchCount:  0,
			})
		}
	}

	addRules(rules.PreToolUse, "PreToolUse")
	addRules(rules.PostToolUse, "PostToolUse")
	addRules(rules.UserPromptSubmit, "UserPromptSubmit")
	addRules(rules.Stop, "Stop")
	addRules(rules.SubagentStop, "SubagentStop")
	addRules(rules.Notification, "Notification")
	addRules(rules.SessionStart, "SessionStart")
	addRules(rules.SessionEnd, "SessionEnd")

	// Add sequence rules
	for _, rule := range sequenceRules {
		resp = append(resp, RuleResponse{
			Name:        rule.Name,
			Description: rule.Description,
			Enabled:     rule.Enabled,
			EventType:   "SequenceRule",
			Decision:    rule.Decision,
			MatchCount:  0,
		})
	}

	return resp
}

// Stats handles the aggregate statistics endpoint
func (h *Handlers) Stats(w http.ResponseWriter, r *http.Request) {
	resp := StatsResponse{
		EventsByType:    make(map[string]int),
		DecisionCounts:  make(map[string]int),
		TopRulesMatched: []RuleMatch{},
	}

	if h.store == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	sessions, err := h.store.ListSessions()
	if err != nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	resp.TotalSessions = len(sessions)

	now := time.Now()
	activeThreshold := now.Add(-1 * time.Hour)
	last24h := now.Add(-24 * time.Hour)

	ruleMatchCounts := make(map[string]int)

	for _, s := range sessions {
		if s.LastSeenAt.After(activeThreshold) {
			resp.ActiveSessions++
		}

		events, _ := h.store.GetRecentEvents(s.SessionID, 10000)
		resp.TotalEvents += len(events)

		for _, e := range events {
			resp.EventsByType[string(e.EventType)]++

			if e.Decision != "" {
				resp.DecisionCounts[e.Decision]++
			}

			if e.Decision == "deny" || e.Decision == "block" {
				resp.Violations++
				if e.Timestamp.After(last24h) {
					resp.Violations24h++
				}
			}

			if e.Timestamp.After(last24h) {
				resp.Events24h++
			}

			if e.RuleMatched != "" {
				ruleMatchCounts[e.RuleMatched]++
			}
		}
	}

	// Get top 10 rules by match count
	for ruleName, count := range ruleMatchCounts {
		resp.TopRulesMatched = append(resp.TopRulesMatched, RuleMatch{
			RuleName:   ruleName,
			MatchCount: count,
		})
	}

	// Sort by match count descending
	for i := 0; i < len(resp.TopRulesMatched)-1; i++ {
		for j := i + 1; j < len(resp.TopRulesMatched); j++ {
			if resp.TopRulesMatched[j].MatchCount > resp.TopRulesMatched[i].MatchCount {
				resp.TopRulesMatched[i], resp.TopRulesMatched[j] = resp.TopRulesMatched[j], resp.TopRulesMatched[i]
			}
		}
	}

	if len(resp.TopRulesMatched) > 10 {
		resp.TopRulesMatched = resp.TopRulesMatched[:10]
	}

	writeJSON(w, http.StatusOK, resp)
}

// EventDetail handles the event detail endpoint
func (h *Handlers) EventDetail(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusNotFound, "store not available")
		return
	}

	// Extract event ID from path - expects /api/events/{id}
	path := r.URL.Path
	idStr := ""

	// Parse the ID from the path
	if len(path) > len("/api/events/") {
		idStr = path[len("/api/events/"):]
	}

	if idStr == "" {
		writeError(w, http.StatusBadRequest, "event id required")
		return
	}

	eventID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid event id")
		return
	}

	event, err := h.store.GetEventByID(eventID)
	if err != nil {
		writeError(w, http.StatusNotFound, "event not found")
		return
	}

	resp := EventDetailResponse{
		ID:           event.ID,
		SessionID:    event.SessionID,
		ToolUseID:    event.ToolUseID,
		EventType:    event.EventType,
		ToolName:     event.ToolName,
		ToolInput:    event.ToolInput,
		ToolResponse: event.ToolResponse,
		Timestamp:    event.Timestamp,
		Decision:     event.Decision,
		RuleMatched:  event.RuleMatched,
	}

	writeJSON(w, http.StatusOK, resp)
}

// ExportEvents handles the events export endpoint
func (h *Handlers) ExportEvents(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeError(w, http.StatusNotFound, "store not available")
		return
	}

	// Parse query parameters
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	sessionID := r.URL.Query().Get("session_id")
	eventType := r.URL.Query().Get("event_type")
	decision := r.URL.Query().Get("decision")
	toolName := r.URL.Query().Get("tool_name")
	sortOrder := r.URL.Query().Get("sort")
	limitStr := r.URL.Query().Get("limit")

	if sortOrder == "" {
		sortOrder = "desc"
	}

	limit := 10000 // Higher default for exports
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	opts := trace.EventFilterOptions{
		SessionID: sessionID,
		EventType: eventType,
		Decision:  decision,
		ToolName:  toolName,
		SortOrder: sortOrder,
		Limit:     limit,
	}

	events, err := h.store.GetFilteredEvents(opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	switch format {
	case "csv":
		h.exportCSV(w, events)
	default:
		h.exportJSON(w, events)
	}
}

func (h *Handlers) exportJSON(w http.ResponseWriter, events []*trace.Event) {
	resp := make([]EventDetailResponse, 0, len(events))
	for _, e := range events {
		resp = append(resp, EventDetailResponse{
			ID:           e.ID,
			SessionID:    e.SessionID,
			ToolUseID:    e.ToolUseID,
			EventType:    e.EventType,
			ToolName:     e.ToolName,
			ToolInput:    e.ToolInput,
			ToolResponse: e.ToolResponse,
			Timestamp:    e.Timestamp,
			Decision:     e.Decision,
			RuleMatched:  e.RuleMatched,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=hooksy-events.json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *Handlers) exportCSV(w http.ResponseWriter, events []*trace.Event) {
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=hooksy-events.csv")

	// Write CSV header
	_, _ = w.Write([]byte("id,session_id,tool_use_id,event_type,tool_name,timestamp,decision,rule_matched\n"))

	// Write each event as a CSV row
	for _, e := range events {
		line := fmt.Sprintf("%d,%s,%s,%s,%s,%s,%s,%s\n",
			e.ID,
			csvEscape(e.SessionID),
			csvEscape(e.ToolUseID),
			csvEscape(string(e.EventType)),
			csvEscape(e.ToolName),
			e.Timestamp.Format(time.RFC3339),
			csvEscape(e.Decision),
			csvEscape(e.RuleMatched),
		)
		_, _ = w.Write([]byte(line))
	}
}

func csvEscape(s string) string {
	// Simple CSV escaping - wrap in quotes if contains comma, quote, or newline
	needsQuote := false
	for _, c := range s {
		if c == ',' || c == '"' || c == '\n' || c == '\r' {
			needsQuote = true
			break
		}
	}

	if needsQuote {
		// Escape quotes by doubling them
		escaped := ""
		for _, c := range s {
			if c == '"' {
				escaped += "\"\""
			} else {
				escaped += string(c)
			}
		}
		return "\"" + escaped + "\""
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
