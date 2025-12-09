package config

import (
	"testing"

	"github.com/ihavespoons/hooksy/internal/hooks"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg == nil {
		t.Fatal("DefaultConfig returned nil")
	}

	if cfg.Version != "1" {
		t.Errorf("got Version=%q, want \"1\"", cfg.Version)
	}

	if cfg.Settings.LogLevel != "info" {
		t.Errorf("got LogLevel=%q, want \"info\"", cfg.Settings.LogLevel)
	}

	if cfg.Settings.DefaultDecision != "allow" {
		t.Errorf("got DefaultDecision=%q, want \"allow\"", cfg.Settings.DefaultDecision)
	}
}

func TestRules_GetRulesForEvent(t *testing.T) {
	preToolUseRules := []Rule{
		{Name: "pre-rule-1", Enabled: true},
		{Name: "pre-rule-2", Enabled: true},
	}
	postToolUseRules := []Rule{
		{Name: "post-rule-1", Enabled: true},
	}
	userPromptRules := []Rule{
		{Name: "prompt-rule-1", Enabled: true},
	}
	stopRules := []Rule{
		{Name: "stop-rule-1", Enabled: true},
	}
	subagentStopRules := []Rule{
		{Name: "subagent-rule-1", Enabled: true},
	}
	notificationRules := []Rule{
		{Name: "notification-rule-1", Enabled: true},
	}
	sessionStartRules := []Rule{
		{Name: "session-start-rule-1", Enabled: true},
	}
	sessionEndRules := []Rule{
		{Name: "session-end-rule-1", Enabled: true},
	}

	rules := Rules{
		PreToolUse:       preToolUseRules,
		PostToolUse:      postToolUseRules,
		UserPromptSubmit: userPromptRules,
		Stop:             stopRules,
		SubagentStop:     subagentStopRules,
		Notification:     notificationRules,
		SessionStart:     sessionStartRules,
		SessionEnd:       sessionEndRules,
	}

	tests := []struct {
		event hooks.EventType
		want  []Rule
	}{
		{hooks.PreToolUse, preToolUseRules},
		{hooks.PostToolUse, postToolUseRules},
		{hooks.UserPromptSubmit, userPromptRules},
		{hooks.Stop, stopRules},
		{hooks.SubagentStop, subagentStopRules},
		{hooks.Notification, notificationRules},
		{hooks.SessionStart, sessionStartRules},
		{hooks.SessionEnd, sessionEndRules},
		{hooks.PreCompact, nil},            // Not in Rules struct
		{hooks.PermissionRequest, nil},     // Not in Rules struct
		{hooks.EventType("Unknown"), nil},  // Unknown event
	}

	for _, tt := range tests {
		t.Run(string(tt.event), func(t *testing.T) {
			got := rules.GetRulesForEvent(tt.event)
			if len(got) != len(tt.want) {
				t.Errorf("got %d rules, want %d", len(got), len(tt.want))
				return
			}
			for i, r := range got {
				if r.Name != tt.want[i].Name {
					t.Errorf("got rule[%d].Name=%q, want %q", i, r.Name, tt.want[i].Name)
				}
			}
		})
	}
}

func TestRules_GetRulesForEvent_Empty(t *testing.T) {
	rules := Rules{}

	got := rules.GetRulesForEvent(hooks.PreToolUse)
	if got != nil {
		t.Errorf("expected nil for empty rules, got %v", got)
	}
}

func TestRule_Fields(t *testing.T) {
	rule := Rule{
		Name:        "test-rule",
		Description: "A test rule",
		Enabled:     true,
		Priority:    100,
		Decision:    "deny",
		Action:      "modify",
		Conditions: Conditions{
			ToolName: "^Bash$",
			ToolInput: map[string][]PatternMatch{
				"command": {
					{Pattern: `rm.*`, Message: "rm detected"},
				},
			},
		},
		SystemMessage: "Access denied",
		Modifications: &Modifications{
			ToolInput: map[string]ModifyAction{
				"command": {Append: " --dry-run"},
			},
		},
	}

	if rule.Name != "test-rule" {
		t.Errorf("got Name=%q, want \"test-rule\"", rule.Name)
	}
	if rule.Priority != 100 {
		t.Errorf("got Priority=%d, want 100", rule.Priority)
	}
	if rule.Decision != "deny" {
		t.Errorf("got Decision=%q, want \"deny\"", rule.Decision)
	}
	if rule.Conditions.ToolName != "^Bash$" {
		t.Errorf("got ToolName=%q, want \"^Bash$\"", rule.Conditions.ToolName)
	}
	if rule.Modifications == nil {
		t.Error("Modifications is nil")
	}
	if rule.Modifications.ToolInput["command"].Append != " --dry-run" {
		t.Error("Modifications.ToolInput not set correctly")
	}
}

func TestConditions_Fields(t *testing.T) {
	conditions := Conditions{
		ToolName: "^Read$",
		ToolInput: map[string][]PatternMatch{
			"file_path": {
				{Pattern: `\.env$`, Message: "env file"},
			},
		},
		ToolResponse: []PatternMatch{
			{Pattern: `password`, Message: "password in output"},
		},
		Prompt: []PatternMatch{
			{Pattern: `ignore`, Message: "injection attempt"},
		},
	}

	if conditions.ToolName != "^Read$" {
		t.Errorf("got ToolName=%q, want \"^Read$\"", conditions.ToolName)
	}
	if len(conditions.ToolInput) != 1 {
		t.Errorf("got %d ToolInput fields, want 1", len(conditions.ToolInput))
	}
	if len(conditions.ToolInput["file_path"]) != 1 {
		t.Error("file_path patterns not set correctly")
	}
	if len(conditions.ToolResponse) != 1 {
		t.Errorf("got %d ToolResponse patterns, want 1", len(conditions.ToolResponse))
	}
	if len(conditions.Prompt) != 1 {
		t.Errorf("got %d Prompt patterns, want 1", len(conditions.Prompt))
	}
}

func TestPatternMatch_Fields(t *testing.T) {
	pm := PatternMatch{
		Pattern: `AKIA[0-9A-Z]{16}`,
		Message: "AWS access key detected",
	}

	if pm.Pattern != `AKIA[0-9A-Z]{16}` {
		t.Errorf("got Pattern=%q, want AKIA pattern", pm.Pattern)
	}
	if pm.Message != "AWS access key detected" {
		t.Errorf("got Message=%q, want \"AWS access key detected\"", pm.Message)
	}
}

func TestModifications_Fields(t *testing.T) {
	mods := Modifications{
		ToolInput: map[string]ModifyAction{
			"command": {
				Append:  " --dry-run",
				Prepend: "sudo ",
				Replace: "new-value",
			},
		},
	}

	if mods.ToolInput == nil {
		t.Fatal("ToolInput is nil")
	}
	action := mods.ToolInput["command"]
	if action.Append != " --dry-run" {
		t.Errorf("got Append=%q, want \" --dry-run\"", action.Append)
	}
	if action.Prepend != "sudo " {
		t.Errorf("got Prepend=%q, want \"sudo \"", action.Prepend)
	}
	if action.Replace != "new-value" {
		t.Errorf("got Replace=%q, want \"new-value\"", action.Replace)
	}
}

func TestSettings_Fields(t *testing.T) {
	settings := Settings{
		LogLevel:        "debug",
		LogFile:         "/var/log/hooksy.log",
		DefaultDecision: "deny",
	}

	if settings.LogLevel != "debug" {
		t.Errorf("got LogLevel=%q, want \"debug\"", settings.LogLevel)
	}
	if settings.LogFile != "/var/log/hooksy.log" {
		t.Errorf("got LogFile=%q, want \"/var/log/hooksy.log\"", settings.LogFile)
	}
	if settings.DefaultDecision != "deny" {
		t.Errorf("got DefaultDecision=%q, want \"deny\"", settings.DefaultDecision)
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := Config{
		Version: "1",
		Settings: Settings{
			LogLevel:        "info",
			DefaultDecision: "allow",
		},
		Rules: Rules{
			PreToolUse: []Rule{
				{Name: "rule-1", Enabled: true},
			},
		},
		Allowlist: []Rule{
			{Name: "allow-1", Enabled: true},
		},
	}

	if cfg.Version != "1" {
		t.Errorf("got Version=%q, want \"1\"", cfg.Version)
	}
	if len(cfg.Rules.PreToolUse) != 1 {
		t.Errorf("got %d PreToolUse rules, want 1", len(cfg.Rules.PreToolUse))
	}
	if len(cfg.Allowlist) != 1 {
		t.Errorf("got %d Allowlist rules, want 1", len(cfg.Allowlist))
	}
}
