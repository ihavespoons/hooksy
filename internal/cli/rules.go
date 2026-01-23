package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/engine"
	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage security rules",
	Long:  "Commands for listing and testing security rules.",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all active rules",
	RunE:  runRulesList,
}

var (
	testRuleName  string
	testInputFile string
	testEventType string
)

var rulesTestCmd = &cobra.Command{
	Use:   "test",
	Short: "Test a rule against sample input",
	Long: `Test a security rule against sample input.

Example:
  hooksy rules test --event PreToolUse --input sample.json`,
	RunE: runRulesTest,
}

func init() {
	rulesTestCmd.Flags().StringVar(&testRuleName, "rule", "", "Specific rule name to test (optional)")
	rulesTestCmd.Flags().StringVarP(&testInputFile, "input", "i", "", "JSON file with sample input (required)")
	rulesTestCmd.Flags().StringVarP(&testEventType, "event", "e", "", "Event type (required)")
	_ = rulesTestCmd.MarkFlagRequired("input")
	_ = rulesTestCmd.MarkFlagRequired("event")

	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesTestCmd)
	rootCmd.AddCommand(rulesCmd)
}

func runRulesList(cmd *cobra.Command, args []string) error {
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
		cfg = config.DefaultConfig()
	}

	printRules := func(name string, rules []config.Rule) {
		if len(rules) == 0 {
			return
		}
		fmt.Printf("\n%s:\n", name)
		for _, r := range rules {
			status := "enabled"
			if !r.Enabled {
				status = "disabled"
			}
			fmt.Printf("  - %s [%s] (priority: %d, decision: %s)\n", r.Name, status, r.Priority, r.Decision)
			if r.Description != "" {
				fmt.Printf("    %s\n", r.Description)
			}
		}
	}

	fmt.Println("Active Security Rules")
	fmt.Println("=====================")

	printRules("PreToolUse", cfg.Rules.PreToolUse)
	printRules("PostToolUse", cfg.Rules.PostToolUse)
	printRules("UserPromptSubmit", cfg.Rules.UserPromptSubmit)
	printRules("Stop", cfg.Rules.Stop)
	printRules("SubagentStop", cfg.Rules.SubagentStop)
	printRules("Notification", cfg.Rules.Notification)
	printRules("SessionStart", cfg.Rules.SessionStart)
	printRules("SessionEnd", cfg.Rules.SessionEnd)

	if len(cfg.Allowlist) > 0 {
		fmt.Printf("\nAllowlist:\n")
		for _, r := range cfg.Allowlist {
			status := "enabled"
			if !r.Enabled {
				status = "disabled"
			}
			fmt.Printf("  - %s [%s]\n", r.Name, status)
			if r.Description != "" {
				fmt.Printf("    %s\n", r.Description)
			}
		}
	}

	fmt.Printf("\nDefault decision: %s\n", cfg.Settings.DefaultDecision)

	return nil
}

func runRulesTest(cmd *cobra.Command, args []string) error {
	// Load config first so we can use log settings
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
		cfg = config.DefaultConfig()
	}

	// Initialize logging with config settings (always debug for rule testing)
	_ = logger.Init("debug", cfg.Settings.LogFile)

	// Read input file
	inputData, err := os.ReadFile(testInputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Validate event type
	event := hooks.EventType(testEventType)

	// Run inspection
	eng := engine.NewEngine(cfg)
	output, err := eng.Inspect(event, inputData)
	if err != nil {
		return fmt.Errorf("inspection failed: %w", err)
	}

	// Print result
	fmt.Println("\nTest Result:")
	fmt.Println("============")

	outputJSON, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal output: %w", err)
	}

	fmt.Println(string(outputJSON))

	return nil
}
