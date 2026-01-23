package trace

import (
	"strings"

	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
)

// IntentChecker compares PreToolUse intent with PostToolUse results
type IntentChecker struct {
	store SessionStore
}

// NewIntentChecker creates a new intent checker
func NewIntentChecker(store SessionStore) *IntentChecker {
	return &IntentChecker{store: store}
}

// IntentMismatch describes a detected mismatch between intent and action
type IntentMismatch struct {
	PreEvent      *Event
	PostEvent     *Event
	MismatchType  string // file_mismatch, command_mismatch, unexpected_output
	Description   string
	Severity      string // critical, warning, info
}

// CheckIntentMismatch checks for mismatches between PreToolUse and PostToolUse events
// with the same tool_use_id. Returns nil if no mismatch detected.
func (c *IntentChecker) CheckIntentMismatch(sessionID string, postEvent *Event) *IntentMismatch {
	if postEvent.EventType != hooks.PostToolUse {
		return nil
	}

	if postEvent.ToolUseID == "" {
		return nil
	}

	// Find the corresponding PreToolUse event
	preEvent, err := c.store.GetEventByToolUseID(sessionID, postEvent.ToolUseID)
	if err != nil {
		logger.Debug().
			Err(err).
			Str("tool_use_id", postEvent.ToolUseID).
			Msg("No PreToolUse event found for correlation")
		return nil
	}

	// Check for various types of mismatches
	if mismatch := c.checkToolNameMismatch(preEvent, postEvent); mismatch != nil {
		return mismatch
	}

	if mismatch := c.checkFileMismatch(preEvent, postEvent); mismatch != nil {
		return mismatch
	}

	if mismatch := c.checkCommandMismatch(preEvent, postEvent); mismatch != nil {
		return mismatch
	}

	if mismatch := c.checkUnexpectedOutput(preEvent, postEvent); mismatch != nil {
		return mismatch
	}

	return nil
}

// checkToolNameMismatch checks if the tool name changed between pre and post
func (c *IntentChecker) checkToolNameMismatch(pre, post *Event) *IntentMismatch {
	if pre.ToolName != post.ToolName {
		return &IntentMismatch{
			PreEvent:     pre,
			PostEvent:    post,
			MismatchType: "tool_name_mismatch",
			Description:  "Tool name changed from '" + pre.ToolName + "' to '" + post.ToolName + "'",
			Severity:     "critical",
		}
	}
	return nil
}

// checkFileMismatch checks if file paths accessed differ from what was requested
func (c *IntentChecker) checkFileMismatch(pre, post *Event) *IntentMismatch {
	// Only check for file-related tools
	fileTools := map[string]bool{
		"Read":  true,
		"Write": true,
		"Edit":  true,
		"Glob":  true,
	}

	if !fileTools[pre.ToolName] {
		return nil
	}

	preFile := getStringField(pre.ToolInput, "file_path")
	postFile := getStringField(post.ToolInput, "file_path")

	if preFile == "" || postFile == "" {
		return nil
	}

	// Check if the actual file differs from requested
	if preFile != postFile {
		return &IntentMismatch{
			PreEvent:     pre,
			PostEvent:    post,
			MismatchType: "file_mismatch",
			Description:  "File path changed from '" + preFile + "' to '" + postFile + "'",
			Severity:     "critical",
		}
	}

	return nil
}

// checkCommandMismatch checks if Bash commands differ significantly
func (c *IntentChecker) checkCommandMismatch(pre, post *Event) *IntentMismatch {
	if pre.ToolName != "Bash" {
		return nil
	}

	preCmd := getStringField(pre.ToolInput, "command")
	postCmd := getStringField(post.ToolInput, "command")

	if preCmd == "" || postCmd == "" {
		return nil
	}

	// Check if command changed
	if preCmd != postCmd {
		return &IntentMismatch{
			PreEvent:     pre,
			PostEvent:    post,
			MismatchType: "command_mismatch",
			Description:  "Command changed between PreToolUse and PostToolUse",
			Severity:     "critical",
		}
	}

	return nil
}

// checkUnexpectedOutput detects potentially deceptive outputs
func (c *IntentChecker) checkUnexpectedOutput(pre, post *Event) *IntentMismatch {
	if post.ToolResponse == nil {
		return nil
	}

	// Check for error indicators that might indicate attempted obfuscation
	response := flattenMap(post.ToolResponse)

	// Look for signs of sandboxing/virtualization detection
	sandboxIndicators := []string{
		"sandbox detected",
		"virtual machine",
		"debugger",
		"analysis environment",
	}

	responseLower := strings.ToLower(response)
	for _, indicator := range sandboxIndicators {
		if strings.Contains(responseLower, indicator) {
			return &IntentMismatch{
				PreEvent:     pre,
				PostEvent:    post,
				MismatchType: "suspicious_output",
				Description:  "Response contains sandbox/analysis detection indicators",
				Severity:     "warning",
			}
		}
	}

	// Check for very large responses on Read operations (potential data exfiltration staging)
	if pre.ToolName == "Read" {
		content := getStringField(post.ToolResponse, "content")
		if len(content) > 100000 { // 100KB threshold
			return &IntentMismatch{
				PreEvent:     pre,
				PostEvent:    post,
				MismatchType: "large_data_access",
				Description:  "Unusually large file content accessed",
				Severity:     "info",
			}
		}
	}

	return nil
}

// AnalyzeIntentSequence analyzes a sequence of correlated events for intent mismatches
func (c *IntentChecker) AnalyzeIntentSequence(sessionID string, events []*Event) []*IntentMismatch {
	var mismatches []*IntentMismatch

	// Build map of PreToolUse events by tool_use_id
	preEvents := make(map[string]*Event)
	for _, event := range events {
		if event.EventType == hooks.PreToolUse && event.ToolUseID != "" {
			preEvents[event.ToolUseID] = event
		}
	}

	// Check each PostToolUse event for mismatches
	for _, event := range events {
		if event.EventType == hooks.PostToolUse && event.ToolUseID != "" {
			if preEvent, ok := preEvents[event.ToolUseID]; ok {
				// Create a temporary checker with pre-loaded events
				if mismatch := c.checkCorrelatedEvents(preEvent, event); mismatch != nil {
					mismatches = append(mismatches, mismatch)
				}
			}
		}
	}

	return mismatches
}

// checkCorrelatedEvents checks a Pre/Post pair for mismatches
func (c *IntentChecker) checkCorrelatedEvents(pre, post *Event) *IntentMismatch {
	if mismatch := c.checkToolNameMismatch(pre, post); mismatch != nil {
		return mismatch
	}
	if mismatch := c.checkFileMismatch(pre, post); mismatch != nil {
		return mismatch
	}
	if mismatch := c.checkCommandMismatch(pre, post); mismatch != nil {
		return mismatch
	}
	if mismatch := c.checkUnexpectedOutput(pre, post); mismatch != nil {
		return mismatch
	}
	return nil
}

// getStringField safely extracts a string field from a map
func getStringField(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// flattenMap converts a map to a searchable string
func flattenMap(m map[string]interface{}) string {
	if m == nil {
		return ""
	}
	var parts []string
	for k, v := range m {
		switch val := v.(type) {
		case string:
			parts = append(parts, k+":"+val)
		case map[string]interface{}:
			parts = append(parts, k+":"+flattenMap(val))
		}
	}
	return strings.Join(parts, " ")
}
