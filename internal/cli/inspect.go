package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/engine"
	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/ihavespoons/hooksy/internal/trace"
	"github.com/spf13/cobra"
)

var (
	eventType string
	dryRun    bool
)

var inspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect a hook event from Claude Code",
	Long: `Inspect a hook event from Claude Code.

This command reads JSON from stdin (the hook input from Claude Code),
evaluates it against configured security rules, and outputs a decision
as JSON to stdout.

Example:
  echo '{"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}}' | hooksy inspect --event PreToolUse`,
	RunE: runInspect,
}

func init() {
	inspectCmd.Flags().StringVarP(&eventType, "event", "e", "", "Hook event type (required)")
	inspectCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would happen without blocking")
	_ = inspectCmd.MarkFlagRequired("event")
	rootCmd.AddCommand(inspectCmd)
}

func runInspect(cmd *cobra.Command, args []string) error {
	// Initialize logging
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	// Validate event type
	event := hooks.EventType(eventType)
	if !isValidEventType(event) {
		return fmt.Errorf("invalid event type: %s", eventType)
	}

	// Load configuration
	loader, err := config.NewLoader(projectDir)
	if err != nil {
		return fmt.Errorf("failed to create config loader: %w", err)
	}

	var cfg *config.Config
	if configFile != "" {
		cfg, err = loader.LoadFromFile(configFile)
	} else {
		cfg, err = loader.Load()
	}
	if err != nil {
		// If no config found, use defaults
		logger.Debug().Msg("No config found, using defaults")
		cfg = config.DefaultConfig()
	}

	// Read input from stdin
	inputJSON, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if len(inputJSON) == 0 {
		return fmt.Errorf("no input received from stdin")
	}

	logger.Debug().
		Str("event", eventType).
		RawJSON("input", inputJSON).
		Msg("Received hook input")

	// Initialize trace store if tracing is enabled
	var store trace.SessionStore
	if cfg.Settings.Trace.Enabled {
		var err error
		store, err = trace.NewSQLiteStore(cfg.Settings.Trace.StoragePath)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to initialize trace store, continuing without tracing")
		} else {
			defer func() { _ = store.Close() }()
		}
	}

	// Run inspection
	eng := engine.NewEngineWithTracing(cfg, store)
	output, err := eng.Inspect(event, inputJSON)
	if err != nil {
		logger.Error().Err(err).Msg("Inspection failed")
		return err
	}

	// In dry-run mode, always allow but show what would have happened
	if dryRun && output.HookSpecificOutput != nil {
		if output.HookSpecificOutput.PermissionDecision == hooks.PermissionDeny {
			logger.Info().
				Str("would_deny", output.HookSpecificOutput.PermissionDecisionReason).
				Msg("Dry run: would deny")
			output = hooks.NewAllowOutput(event, "[DRY RUN] Would deny: "+output.HookSpecificOutput.PermissionDecisionReason)
		}
	}

	// Output result as JSON to stdout
	outputJSON, err := json.Marshal(output)
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	fmt.Println(string(outputJSON))
	return nil
}

func isValidEventType(event hooks.EventType) bool {
	switch event {
	case hooks.PreToolUse, hooks.PostToolUse, hooks.UserPromptSubmit,
		hooks.Stop, hooks.SubagentStop, hooks.Notification,
		hooks.PreCompact, hooks.SessionStart, hooks.SessionEnd,
		hooks.PermissionRequest:
		return true
	default:
		return false
	}
}
