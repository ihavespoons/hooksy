package cli

import (
	"fmt"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/ihavespoons/hooksy/internal/config"
)

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration files",
	Long: `Validate hooksy configuration files.

Checks that the configuration files are valid YAML and that all
regex patterns compile correctly.`,
	RunE: runValidate,
}

func init() {
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	loader, err := config.NewLoader(projectDir)
	if err != nil {
		return fmt.Errorf("failed to create config loader: %w", err)
	}

	var cfg *config.Config
	var configPath string

	if configFile != "" {
		configPath = configFile
		cfg, err = loader.LoadFromFile(configFile)
	} else {
		// Check both global and project configs
		globalPath := loader.GlobalConfigPath()
		projectPath := loader.ProjectConfigPath()

		if config.Exists(globalPath) {
			fmt.Printf("Validating global config: %s\n", globalPath)
			if err := validateConfigFile(loader, globalPath); err != nil {
				return err
			}
			fmt.Println("  Valid!")
		}

		if config.Exists(projectPath) {
			fmt.Printf("Validating project config: %s\n", projectPath)
			if err := validateConfigFile(loader, projectPath); err != nil {
				return err
			}
			fmt.Println("  Valid!")
		}

		if !config.Exists(globalPath) && !config.Exists(projectPath) {
			fmt.Println("No configuration files found.")
			fmt.Println("Run 'hooksy init' to create one.")
			return nil
		}

		return nil
	}

	if err != nil {
		return fmt.Errorf("failed to load config from %s: %w", configPath, err)
	}

	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	fmt.Printf("Configuration is valid: %s\n", configPath)
	return nil
}

func validateConfigFile(loader *config.Loader, path string) error {
	cfg, err := loader.LoadFromFile(path)
	if err != nil {
		return fmt.Errorf("  Failed to parse: %w", err)
	}

	if err := validateConfig(cfg); err != nil {
		return fmt.Errorf("  Invalid: %w", err)
	}

	return nil
}

func validateConfig(cfg *config.Config) error {
	// Validate all rules
	allRules := [][]config.Rule{
		cfg.Rules.PreToolUse,
		cfg.Rules.PostToolUse,
		cfg.Rules.UserPromptSubmit,
		cfg.Rules.Stop,
		cfg.Rules.SubagentStop,
		cfg.Rules.Notification,
		cfg.Rules.SessionStart,
		cfg.Rules.SessionEnd,
		cfg.Allowlist,
	}

	for _, rules := range allRules {
		for _, rule := range rules {
			if err := validateRule(&rule); err != nil {
				return fmt.Errorf("rule '%s': %w", rule.Name, err)
			}
		}
	}

	return nil
}

func validateRule(rule *config.Rule) error {
	// Validate tool name pattern
	if rule.Conditions.ToolName != "" {
		if _, err := regexp.Compile(rule.Conditions.ToolName); err != nil {
			return fmt.Errorf("invalid tool_name pattern: %w", err)
		}
	}

	// Validate tool input patterns
	for field, patterns := range rule.Conditions.ToolInput {
		for _, p := range patterns {
			if _, err := regexp.Compile(p.Pattern); err != nil {
				return fmt.Errorf("invalid tool_input.%s pattern %q: %w", field, p.Pattern, err)
			}
		}
	}

	// Validate tool response patterns
	for _, p := range rule.Conditions.ToolResponse {
		if _, err := regexp.Compile(p.Pattern); err != nil {
			return fmt.Errorf("invalid tool_response pattern %q: %w", p.Pattern, err)
		}
	}

	// Validate prompt patterns
	for _, p := range rule.Conditions.Prompt {
		if _, err := regexp.Compile(p.Pattern); err != nil {
			return fmt.Errorf("invalid prompt pattern %q: %w", p.Pattern, err)
		}
	}

	// Validate decision
	switch rule.Decision {
	case "allow", "deny", "ask", "block", "":
		// Valid
	default:
		return fmt.Errorf("invalid decision: %s (must be allow, deny, ask, or block)", rule.Decision)
	}

	return nil
}
