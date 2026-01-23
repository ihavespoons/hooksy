package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	events string
)

var generateCmd = &cobra.Command{
	Use:   "generate-hooks",
	Short: "Generate Claude Code hook configuration",
	Long: `Generate the hook configuration to add to Claude Code settings.

This outputs JSON that can be added to your Claude Code settings file
to integrate hooksy as a security inspector.

Example:
  hooksy generate-hooks --events PreToolUse,PostToolUse,UserPromptSubmit`,
	RunE: runGenerate,
}

func init() {
	generateCmd.Flags().StringVarP(&events, "events", "e", "PreToolUse,PostToolUse,UserPromptSubmit", "Comma-separated list of events to hook")
	rootCmd.AddCommand(generateCmd)
}

// HookConfig represents the Claude Code hooks configuration structure
type HookConfig struct {
	Hooks map[string][]EventConfig `json:"hooks"`
}

// EventConfig represents configuration for a specific event type
type EventConfig struct {
	Matcher string        `json:"matcher,omitempty"`
	Hooks   []HookCommand `json:"hooks"`
}

// HookCommand represents a single hook command to execute
type HookCommand struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

func runGenerate(cmd *cobra.Command, args []string) error {
	eventList := strings.Split(events, ",")

	hookConfig := HookConfig{
		Hooks: make(map[string][]EventConfig),
	}

	for _, event := range eventList {
		event = strings.TrimSpace(event)
		if event == "" {
			continue
		}

		eventConfig := EventConfig{
			Hooks: []HookCommand{
				{
					Type:    "command",
					Command: fmt.Sprintf("hooksy inspect --event %s", event),
					Timeout: 30,
				},
			},
		}

		// Add matcher for tool-based events
		switch event {
		case "PreToolUse", "PostToolUse", "PermissionRequest":
			eventConfig.Matcher = ".*"
		}

		hookConfig.Hooks[event] = []EventConfig{eventConfig}
	}

	output, err := json.MarshalIndent(hookConfig, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal hook config: %w", err)
	}

	fmt.Println("Add the following to your Claude Code settings file:")
	fmt.Println()
	fmt.Println(string(output))
	fmt.Println()
	fmt.Println("Settings file locations:")
	fmt.Println("  - Global: ~/.claude/settings.json")
	fmt.Println("  - Project: .claude/settings.json")
	fmt.Println()
	fmt.Println("Note: Merge with existing settings if present.")

	return nil
}
