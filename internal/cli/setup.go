package cli

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ihavespoons/hooksy/internal/config"
)

//go:embed configs/*.yaml
var configFiles embed.FS

var (
	setupGlobal        bool
	setupProfile       string
	setupComprehensive bool
	setupEvents        string
	setupForce         bool
)

// Profile descriptions for user output
var profileDescriptions = map[string]string{
	"default":        "Balanced protection (starter rules, no tracing)",
	"strict":         "Maximum security (deny by default, explicit allowlist)",
	"trace-analysis": "Tracing enabled + sequence rules for attack detection",
	"llm-example":    "LLM-enhanced analysis with provider config",
}

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Set up hooksy configuration and Claude Code hooks",
	Long: `Set up hooksy with a single command.

This unified command:
1. Creates a hooksy configuration file (.hooksy/config.yaml or global)
2. Outputs Claude Code hooks JSON for copy/paste into settings

Profiles:
  default        - Balanced protection (starter rules, no tracing)
  strict         - Maximum security (deny by default, explicit allowlist)
  trace-analysis - Tracing enabled + sequence rules for attack detection
  llm-example    - LLM-enhanced analysis with provider config

Examples:
  hooksy setup                           # Default profile, project config
  hooksy setup --comprehensive           # Trace analysis with sequence rules
  hooksy setup --profile strict          # Strict security profile
  hooksy setup --global                  # Write to ~/.hooksy/config.yaml
  hooksy setup --force                   # Overwrite existing config`,
	RunE: runSetup,
}

func init() {
	setupCmd.Flags().BoolVarP(&setupGlobal, "global", "g", false, "Write config to ~/.hooksy/config.yaml instead of project")
	setupCmd.Flags().StringVar(&setupProfile, "profile", "default", "Profile to use: default, strict, trace-analysis, llm-example")
	setupCmd.Flags().BoolVar(&setupComprehensive, "comprehensive", false, "Enable tracing + sequence rules (shorthand for --profile trace-analysis)")
	setupCmd.Flags().StringVarP(&setupEvents, "events", "e", "PreToolUse,PostToolUse,UserPromptSubmit", "Comma-separated events to hook")
	setupCmd.Flags().BoolVar(&setupForce, "force", false, "Overwrite existing config file")
	rootCmd.AddCommand(setupCmd)
}

func runSetup(cmd *cobra.Command, args []string) error {
	// Comprehensive mode is shorthand for trace-analysis profile
	profile := setupProfile
	if setupComprehensive {
		profile = "trace-analysis"
	}

	// Validate profile
	validProfiles := []string{"default", "strict", "trace-analysis", "llm-example"}
	if !contains(validProfiles, profile) {
		return fmt.Errorf("invalid profile %q: must be one of %v", profile, validProfiles)
	}

	// Determine config path
	var configPath string
	if setupGlobal {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("failed to get home directory: %w", err)
		}
		configPath = filepath.Join(homeDir, ".hooksy", "config.yaml")
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		configPath = filepath.Join(cwd, ".hooksy", "config.yaml")
	}

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		if !setupForce {
			return fmt.Errorf("config file already exists: %s\nUse --force to overwrite", configPath)
		}
	}

	// Load profile config
	cfg, err := loadProfileConfig(profile)
	if err != nil {
		return fmt.Errorf("failed to load profile config: %w", err)
	}

	// Create directory if needed
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	// Output success message
	fmt.Printf("Created hooksy config: %s\n\n", configPath)

	// Output profile info
	profileName := profile
	if setupComprehensive {
		profileName = fmt.Sprintf("%s (comprehensive)", profile)
	}
	fmt.Printf("Profile: %s\n", profileName)
	if desc, ok := profileDescriptions[profile]; ok {
		fmt.Printf("         %s\n", desc)
	}
	fmt.Println()

	// Output features enabled
	fmt.Println("Features enabled:")
	printProfileFeatures(cfg)
	fmt.Println()

	// Generate and output Claude Code hooks JSON
	hookConfig := generateHooksConfig(setupEvents)
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

// loadProfileConfig loads the config for the specified profile
func loadProfileConfig(profile string) (*config.Config, error) {
	// Map profile name to config file
	filename := fmt.Sprintf("configs/%s.yaml", profile)

	data, err := configFiles.ReadFile(filename)
	if err != nil {
		// Fallback to generating default config if embedded file not found
		if profile == "default" {
			return generateStarterConfig(), nil
		}
		return nil, fmt.Errorf("profile %q not found: %w", profile, err)
	}

	var cfg config.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse profile config: %w", err)
	}

	return &cfg, nil
}

// printProfileFeatures prints the enabled features for a config
func printProfileFeatures(cfg *config.Config) {
	// Tracing
	if cfg.Settings.Trace.Enabled {
		storage := cfg.Settings.Trace.StoragePath
		if storage == "" {
			storage = "~/.hooksy/traces/sessions.db"
		}
		fmt.Printf("  - Tracing: enabled (%s)\n", storage)
	} else {
		fmt.Println("  - Tracing: disabled")
	}

	// Sequence rules
	if len(cfg.SequenceRules) > 0 {
		var ruleNames []string
		for _, rule := range cfg.SequenceRules {
			if rule.Enabled {
				ruleNames = append(ruleNames, rule.Name)
			}
		}
		if len(ruleNames) > 0 {
			fmt.Printf("  - Sequence rules: enabled (%s)\n", strings.Join(ruleNames, ", "))
		} else {
			fmt.Println("  - Sequence rules: configured but disabled")
		}
	} else {
		fmt.Println("  - Sequence rules: none")
	}

	// LLM analysis
	if cfg.LLM != nil && cfg.LLM.Enabled {
		fmt.Printf("  - LLM analysis: enabled (mode: %s)\n", cfg.LLM.Mode)
	} else {
		fmt.Println("  - LLM analysis: disabled")
	}

	// Secret detection (check PostToolUse rules)
	hasSecretDetection := false
	for _, rule := range cfg.Rules.PostToolUse {
		if rule.Enabled && len(rule.Conditions.ToolResponse) > 0 {
			hasSecretDetection = true
			break
		}
	}
	if hasSecretDetection {
		fmt.Println("  - Secret detection: enabled")
	} else {
		fmt.Println("  - Secret detection: disabled")
	}

	// Default decision
	fmt.Printf("  - Default decision: %s\n", cfg.Settings.DefaultDecision)
}

// generateHooksConfig generates the Claude Code hooks configuration
func generateHooksConfig(events string) HookConfig {
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

	return hookConfig
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
