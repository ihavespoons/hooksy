package hooks

// EventType represents the type of Claude Code hook event
type EventType string

// Event types for Claude Code hooks
const (
	PreToolUse        EventType = "PreToolUse"
	PostToolUse       EventType = "PostToolUse"
	UserPromptSubmit  EventType = "UserPromptSubmit"
	Stop              EventType = "Stop"
	SubagentStop      EventType = "SubagentStop"
	Notification      EventType = "Notification"
	PreCompact        EventType = "PreCompact"
	SessionStart      EventType = "SessionStart"
	SessionEnd        EventType = "SessionEnd"
	PermissionRequest EventType = "PermissionRequest"
)

// CommonInput contains fields common to all hook events
type CommonInput struct {
	SessionID      string `json:"session_id"`
	TranscriptPath string `json:"transcript_path"`
	Cwd            string `json:"cwd"`
	PermissionMode string `json:"permission_mode"`
	HookEventName  string `json:"hook_event_name"`
}

// PreToolUseInput is the input for PreToolUse hooks
type PreToolUseInput struct {
	CommonInput
	ToolName  string                 `json:"tool_name"`
	ToolInput map[string]interface{} `json:"tool_input"`
	ToolUseID string                 `json:"tool_use_id"`
}

// PostToolUseInput is the input for PostToolUse hooks
type PostToolUseInput struct {
	CommonInput
	ToolName     string                 `json:"tool_name"`
	ToolInput    map[string]interface{} `json:"tool_input"`
	ToolResponse map[string]interface{} `json:"tool_response"`
	ToolUseID    string                 `json:"tool_use_id"`
}

// UserPromptSubmitInput is the input for UserPromptSubmit hooks
type UserPromptSubmitInput struct {
	CommonInput
	Prompt string `json:"prompt"`
}

// StopInput is the input for Stop/SubagentStop hooks
type StopInput struct {
	CommonInput
	StopHookActive bool `json:"stop_hook_active"`
}

// NotificationInput is the input for Notification hooks
type NotificationInput struct {
	CommonInput
	Message          string `json:"message"`
	NotificationType string `json:"notification_type"`
}

// SessionStartInput is the input for SessionStart hooks
type SessionStartInput struct {
	CommonInput
	Source string `json:"source"` // startup, resume, clear, compact
}

// SessionEndInput is the input for SessionEnd hooks
type SessionEndInput struct {
	CommonInput
	Reason string `json:"reason"` // clear, logout, prompt_input_exit, other
}

// PreCompactInput is the input for PreCompact hooks
type PreCompactInput struct {
	CommonInput
	Trigger            string `json:"trigger"` // manual, auto
	CustomInstructions string `json:"custom_instructions"`
}

// PermissionDecision represents the decision type for PreToolUse
type PermissionDecision string

// Permission decision values for PreToolUse hooks
const (
	PermissionAllow PermissionDecision = "allow"
	PermissionDeny  PermissionDecision = "deny"
	PermissionAsk   PermissionDecision = "ask"
)

// Decision represents a blocking decision
type Decision string

// Blocking decision values
const (
	DecisionBlock Decision = "block"
)

// HookOutput is the base output structure for all hooks
type HookOutput struct {
	Continue           bool                `json:"continue"`
	StopReason         string              `json:"stopReason,omitempty"`
	SuppressOutput     bool                `json:"suppressOutput,omitempty"`
	SystemMessage      string              `json:"systemMessage,omitempty"`
	Decision           Decision            `json:"decision,omitempty"`
	Reason             string              `json:"reason,omitempty"`
	HookSpecificOutput *HookSpecificOutput `json:"hookSpecificOutput,omitempty"`
}

// HookSpecificOutput contains event-specific output fields
type HookSpecificOutput struct {
	HookEventName            string                 `json:"hookEventName"`
	PermissionDecision       PermissionDecision     `json:"permissionDecision,omitempty"`
	PermissionDecisionReason string                 `json:"permissionDecisionReason,omitempty"`
	UpdatedInput             map[string]interface{} `json:"updatedInput,omitempty"`
	AdditionalContext        string                 `json:"additionalContext,omitempty"`
}

// NewAllowOutput creates an allow decision output
func NewAllowOutput(eventName EventType, reason string) *HookOutput {
	return &HookOutput{
		Continue: true,
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            string(eventName),
			PermissionDecision:       PermissionAllow,
			PermissionDecisionReason: reason,
		},
	}
}

// NewDenyOutput creates a deny decision output
func NewDenyOutput(eventName EventType, reason string) *HookOutput {
	return &HookOutput{
		Continue: true,
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            string(eventName),
			PermissionDecision:       PermissionDeny,
			PermissionDecisionReason: reason,
		},
	}
}

// NewAskOutput creates an ask decision output (prompt user)
func NewAskOutput(eventName EventType, reason string) *HookOutput {
	return &HookOutput{
		Continue: true,
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            string(eventName),
			PermissionDecision:       PermissionAsk,
			PermissionDecisionReason: reason,
		},
	}
}

// NewBlockOutput creates a blocking output that stops processing
func NewBlockOutput(stopReason, systemMessage string) *HookOutput {
	return &HookOutput{
		Continue:      false,
		StopReason:    stopReason,
		SystemMessage: systemMessage,
	}
}

// NewModifyOutput creates an allow decision with modified input
func NewModifyOutput(eventName EventType, reason string, updatedInput map[string]interface{}) *HookOutput {
	return &HookOutput{
		Continue: true,
		HookSpecificOutput: &HookSpecificOutput{
			HookEventName:            string(eventName),
			PermissionDecision:       PermissionAllow,
			PermissionDecisionReason: reason,
			UpdatedInput:             updatedInput,
		},
	}
}

// NewStopAllowOutput creates an allow output for Stop events (no hookSpecificOutput)
func NewStopAllowOutput() *HookOutput {
	return &HookOutput{
		Continue: true,
	}
}

// NewStopContinueOutput creates an output for Stop events that continues processing
func NewStopContinueOutput(stopReason string) *HookOutput {
	return &HookOutput{
		Continue:   true,
		StopReason: stopReason,
	}
}
