package hooks

import (
	"encoding/json"
	"testing"
)

func TestEventTypeConstants(t *testing.T) {
	tests := []struct {
		event EventType
		want  string
	}{
		{PreToolUse, "PreToolUse"},
		{PostToolUse, "PostToolUse"},
		{UserPromptSubmit, "UserPromptSubmit"},
		{Stop, "Stop"},
		{SubagentStop, "SubagentStop"},
		{Notification, "Notification"},
		{PreCompact, "PreCompact"},
		{SessionStart, "SessionStart"},
		{SessionEnd, "SessionEnd"},
		{PermissionRequest, "PermissionRequest"},
	}

	for _, tt := range tests {
		if string(tt.event) != tt.want {
			t.Errorf("got %q, want %q", string(tt.event), tt.want)
		}
	}
}

func TestPermissionDecisionConstants(t *testing.T) {
	if PermissionAllow != "allow" {
		t.Errorf("PermissionAllow = %q, want \"allow\"", PermissionAllow)
	}
	if PermissionDeny != "deny" {
		t.Errorf("PermissionDeny = %q, want \"deny\"", PermissionDeny)
	}
	if PermissionAsk != "ask" {
		t.Errorf("PermissionAsk = %q, want \"ask\"", PermissionAsk)
	}
}

func TestDecisionConstants(t *testing.T) {
	if DecisionBlock != "block" {
		t.Errorf("DecisionBlock = %q, want \"block\"", DecisionBlock)
	}
}

func TestNewAllowOutput(t *testing.T) {
	output := NewAllowOutput(PreToolUse, "All checks passed")

	if !output.Continue {
		t.Error("Continue should be true")
	}
	if output.HookSpecificOutput == nil {
		t.Fatal("HookSpecificOutput is nil")
	}
	if output.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Errorf("got HookEventName=%q, want \"PreToolUse\"", output.HookSpecificOutput.HookEventName)
	}
	if output.HookSpecificOutput.PermissionDecision != PermissionAllow {
		t.Errorf("got PermissionDecision=%q, want \"allow\"", output.HookSpecificOutput.PermissionDecision)
	}
	if output.HookSpecificOutput.PermissionDecisionReason != "All checks passed" {
		t.Errorf("got PermissionDecisionReason=%q, want \"All checks passed\"", output.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestNewDenyOutput(t *testing.T) {
	output := NewDenyOutput(PreToolUse, "Dangerous command blocked")

	if !output.Continue {
		t.Error("Continue should be true for deny")
	}
	if output.HookSpecificOutput == nil {
		t.Fatal("HookSpecificOutput is nil")
	}
	if output.HookSpecificOutput.PermissionDecision != PermissionDeny {
		t.Errorf("got PermissionDecision=%q, want \"deny\"", output.HookSpecificOutput.PermissionDecision)
	}
	if output.HookSpecificOutput.PermissionDecisionReason != "Dangerous command blocked" {
		t.Errorf("got reason=%q, want \"Dangerous command blocked\"", output.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestNewAskOutput(t *testing.T) {
	output := NewAskOutput(UserPromptSubmit, "Suspicious prompt detected")

	if !output.Continue {
		t.Error("Continue should be true for ask")
	}
	if output.HookSpecificOutput == nil {
		t.Fatal("HookSpecificOutput is nil")
	}
	if output.HookSpecificOutput.HookEventName != "UserPromptSubmit" {
		t.Errorf("got HookEventName=%q, want \"UserPromptSubmit\"", output.HookSpecificOutput.HookEventName)
	}
	if output.HookSpecificOutput.PermissionDecision != PermissionAsk {
		t.Errorf("got PermissionDecision=%q, want \"ask\"", output.HookSpecificOutput.PermissionDecision)
	}
}

func TestNewBlockOutput(t *testing.T) {
	output := NewBlockOutput("Security violation", "Access to sensitive data blocked")

	if output.Continue {
		t.Error("Continue should be false for block")
	}
	if output.StopReason != "Security violation" {
		t.Errorf("got StopReason=%q, want \"Security violation\"", output.StopReason)
	}
	if output.SystemMessage != "Access to sensitive data blocked" {
		t.Errorf("got SystemMessage=%q, want \"Access to sensitive data blocked\"", output.SystemMessage)
	}
	if output.HookSpecificOutput != nil {
		t.Error("HookSpecificOutput should be nil for block")
	}
}

func TestNewModifyOutput(t *testing.T) {
	updatedInput := map[string]interface{}{
		"command": "git push --dry-run",
	}
	output := NewModifyOutput(PreToolUse, "Command modified", updatedInput)

	if !output.Continue {
		t.Error("Continue should be true for modify")
	}
	if output.HookSpecificOutput == nil {
		t.Fatal("HookSpecificOutput is nil")
	}
	if output.HookSpecificOutput.PermissionDecision != PermissionAllow {
		t.Errorf("got PermissionDecision=%q, want \"allow\"", output.HookSpecificOutput.PermissionDecision)
	}
	if output.HookSpecificOutput.UpdatedInput == nil {
		t.Fatal("UpdatedInput is nil")
	}
	if output.HookSpecificOutput.UpdatedInput["command"] != "git push --dry-run" {
		t.Errorf("got UpdatedInput[command]=%v, want \"git push --dry-run\"", output.HookSpecificOutput.UpdatedInput["command"])
	}
}

func TestHookOutput_JSONSerialization(t *testing.T) {
	tests := []struct {
		name   string
		output *HookOutput
		check  func(t *testing.T, data map[string]interface{})
	}{
		{
			name:   "allow output",
			output: NewAllowOutput(PreToolUse, "OK"),
			check: func(t *testing.T, data map[string]interface{}) {
				if data["continue"] != true {
					t.Error("continue should be true")
				}
				hso, ok := data["hookSpecificOutput"].(map[string]interface{})
				if !ok {
					t.Fatal("hookSpecificOutput missing")
				}
				if hso["permissionDecision"] != "allow" {
					t.Error("permissionDecision should be allow")
				}
			},
		},
		{
			name:   "deny output",
			output: NewDenyOutput(PreToolUse, "Blocked"),
			check: func(t *testing.T, data map[string]interface{}) {
				hso, ok := data["hookSpecificOutput"].(map[string]interface{})
				if !ok {
					t.Fatal("hookSpecificOutput missing")
				}
				if hso["permissionDecision"] != "deny" {
					t.Error("permissionDecision should be deny")
				}
			},
		},
		{
			name:   "block output",
			output: NewBlockOutput("Error", "System message"),
			check: func(t *testing.T, data map[string]interface{}) {
				if data["continue"] != false {
					t.Error("continue should be false")
				}
				if data["stopReason"] != "Error" {
					t.Error("stopReason mismatch")
				}
				if data["systemMessage"] != "System message" {
					t.Error("systemMessage mismatch")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonBytes, err := json.Marshal(tt.output)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			var data map[string]interface{}
			if err := json.Unmarshal(jsonBytes, &data); err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			tt.check(t, data)
		})
	}
}

func TestPreToolUseInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"transcript_path": "/tmp/transcript",
		"cwd": "/home/user/project",
		"permission_mode": "default",
		"hook_event_name": "PreToolUse",
		"tool_name": "Bash",
		"tool_input": {"command": "ls -la"},
		"tool_use_id": "tool-456"
	}`

	var input PreToolUseInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if input.SessionID != "sess-123" {
		t.Errorf("got SessionID=%q", input.SessionID)
	}
	if input.ToolName != "Bash" {
		t.Errorf("got ToolName=%q", input.ToolName)
	}
	if input.ToolInput["command"] != "ls -la" {
		t.Errorf("got command=%v", input.ToolInput["command"])
	}
	if input.ToolUseID != "tool-456" {
		t.Errorf("got ToolUseID=%q", input.ToolUseID)
	}
}

func TestPostToolUseInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"tool_name": "Bash",
		"tool_input": {"command": "cat /etc/passwd"},
		"tool_response": {"output": "root:x:0:0:root:/root:/bin/bash"},
		"tool_use_id": "tool-789"
	}`

	var input PostToolUseInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if input.ToolName != "Bash" {
		t.Errorf("got ToolName=%q", input.ToolName)
	}
	if input.ToolResponse["output"] != "root:x:0:0:root:/root:/bin/bash" {
		t.Errorf("got output=%v", input.ToolResponse["output"])
	}
}

func TestUserPromptSubmitInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"prompt": "Help me write a function"
	}`

	var input UserPromptSubmitInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if input.Prompt != "Help me write a function" {
		t.Errorf("got Prompt=%q", input.Prompt)
	}
}

func TestStopInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"stop_hook_active": true
	}`

	var input StopInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if !input.StopHookActive {
		t.Error("StopHookActive should be true")
	}
}

func TestNotificationInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"message": "Build completed",
		"notification_type": "info"
	}`

	var input NotificationInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if input.Message != "Build completed" {
		t.Errorf("got Message=%q", input.Message)
	}
	if input.NotificationType != "info" {
		t.Errorf("got NotificationType=%q", input.NotificationType)
	}
}

func TestSessionStartInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"source": "startup"
	}`

	var input SessionStartInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if input.Source != "startup" {
		t.Errorf("got Source=%q", input.Source)
	}
}

func TestSessionEndInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"reason": "clear"
	}`

	var input SessionEndInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if input.Reason != "clear" {
		t.Errorf("got Reason=%q", input.Reason)
	}
}

func TestPreCompactInput_JSONDeserialization(t *testing.T) {
	jsonData := `{
		"session_id": "sess-123",
		"trigger": "manual",
		"custom_instructions": "Keep important context"
	}`

	var input PreCompactInput
	if err := json.Unmarshal([]byte(jsonData), &input); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if input.Trigger != "manual" {
		t.Errorf("got Trigger=%q", input.Trigger)
	}
	if input.CustomInstructions != "Keep important context" {
		t.Errorf("got CustomInstructions=%q", input.CustomInstructions)
	}
}

func TestHookSpecificOutput_Fields(t *testing.T) {
	hso := HookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       PermissionAllow,
		PermissionDecisionReason: "OK",
		UpdatedInput:             map[string]interface{}{"key": "value"},
		AdditionalContext:        "Extra info",
	}

	if hso.HookEventName != "PreToolUse" {
		t.Errorf("got HookEventName=%q", hso.HookEventName)
	}
	if hso.PermissionDecision != PermissionAllow {
		t.Errorf("got PermissionDecision=%q", hso.PermissionDecision)
	}
	if hso.UpdatedInput["key"] != "value" {
		t.Error("UpdatedInput not set correctly")
	}
	if hso.AdditionalContext != "Extra info" {
		t.Errorf("got AdditionalContext=%q", hso.AdditionalContext)
	}
}

func TestCommonInput_Fields(t *testing.T) {
	common := CommonInput{
		SessionID:      "sess-abc",
		TranscriptPath: "/path/to/transcript",
		Cwd:            "/working/dir",
		PermissionMode: "default",
		HookEventName:  "PreToolUse",
	}

	if common.SessionID != "sess-abc" {
		t.Errorf("got SessionID=%q", common.SessionID)
	}
	if common.TranscriptPath != "/path/to/transcript" {
		t.Errorf("got TranscriptPath=%q", common.TranscriptPath)
	}
	if common.Cwd != "/working/dir" {
		t.Errorf("got Cwd=%q", common.Cwd)
	}
	if common.PermissionMode != "default" {
		t.Errorf("got PermissionMode=%q", common.PermissionMode)
	}
	if common.HookEventName != "PreToolUse" {
		t.Errorf("got HookEventName=%q", common.HookEventName)
	}
}
