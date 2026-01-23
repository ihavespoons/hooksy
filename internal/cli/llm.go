package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/llm"
	"github.com/ihavespoons/hooksy/internal/llm/providers"
	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/spf13/cobra"
)

var llmCmd = &cobra.Command{
	Use:   "llm",
	Short: "LLM provider management commands",
	Long: `Commands for managing and testing LLM providers.

Use these commands to check provider availability, test prompts,
and manage LLM integration settings.`,
}

var llmStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show LLM provider status",
	Long: `Display the status of all configured LLM providers.

Shows which providers are available and ready to use.`,
	RunE: runLLMStatus,
}

var llmTestCmd = &cobra.Command{
	Use:   "test [prompt]",
	Short: "Test a prompt with an LLM provider",
	Long: `Test a prompt with a specific LLM provider.

Example:
  hooksy llm test "Is this safe: rm -rf /"
  hooksy llm test --provider anthropic "Analyze this command"`,
	Args: cobra.ExactArgs(1),
	RunE: runLLMTest,
}

var (
	llmTestProvider string
	llmTestTimeout  int
)

func init() {
	llmTestCmd.Flags().StringVar(&llmTestProvider, "provider", "", "Provider to use (claude_cli, anthropic, openai, huggingface)")
	llmTestCmd.Flags().IntVar(&llmTestTimeout, "timeout", 30, "Timeout in seconds")

	llmCmd.AddCommand(llmStatusCmd)
	llmCmd.AddCommand(llmTestCmd)
	rootCmd.AddCommand(llmCmd)
}

func runLLMStatus(cmd *cobra.Command, args []string) error {
	// Load configuration first so we can use log settings
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

	// Initialize logging with config settings
	logLevel := cfg.Settings.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	if verbose {
		logLevel = "debug"
	}
	_ = logger.Init(logLevel, cfg.Settings.LogFile)

	fmt.Println("LLM Provider Status")
	fmt.Println("==================")
	fmt.Println()

	// Check if LLM is enabled
	if cfg.LLM == nil || !cfg.LLM.Enabled {
		fmt.Println("LLM analysis is DISABLED")
		fmt.Println()
		fmt.Println("To enable LLM analysis, add the following to your config:")
		fmt.Println()
		fmt.Println("  llm:")
		fmt.Println("    enabled: true")
		return nil
	}

	fmt.Println("LLM analysis is ENABLED")
	fmt.Printf("Mode: %s\n", cfg.LLM.Mode)
	fmt.Printf("Provider order: %s\n", formatProviderOrder(cfg.LLM.ProviderOrder))
	fmt.Println()

	// Create manager to check provider status
	manager, err := llm.NewManager(cfg.LLM, providers.DefaultFactories())
	if err != nil {
		return fmt.Errorf("failed to create LLM manager: %w", err)
	}
	defer func() { _ = manager.Close() }()

	ctx := context.Background()
	status := manager.ProviderStatus(ctx)

	fmt.Println("Provider Availability")
	fmt.Println("---------------------")
	for _, pt := range cfg.LLM.ProviderOrder {
		info, ok := status[pt]
		if !ok {
			fmt.Printf("  %-15s: not configured\n", pt)
			continue
		}

		statusStr := "✗ unavailable"
		if info.Available {
			statusStr = "✓ available"
		}
		if info.Reason != "" && !info.Available {
			statusStr += fmt.Sprintf(" (%s)", info.Reason)
		}
		if info.Name != "" {
			fmt.Printf("  %-15s: %s [%s]\n", pt, statusStr, info.Name)
		} else {
			fmt.Printf("  %-15s: %s\n", pt, statusStr)
		}
	}
	fmt.Println()

	// Show budget status if enabled
	budgetStatus := manager.BudgetStatus()
	if budgetStatus != nil {
		fmt.Println("Budget Status")
		fmt.Println("-------------")
		fmt.Printf("  Daily limit:  %d cents\n", budgetStatus.LimitCents)
		fmt.Printf("  Spent today:  %.2f cents\n", budgetStatus.SpentCents)
		fmt.Printf("  Remaining:    %.2f cents\n", budgetStatus.RemainingCents)
		fmt.Printf("  Used:         %.1f%%\n", budgetStatus.PercentUsed)
		if budgetStatus.Exceeded {
			fmt.Println("  ⚠️  Budget exceeded!")
		} else if budgetStatus.Warning {
			fmt.Println("  ⚠️  Approaching budget limit")
		}
		fmt.Println()
	}

	// Show cache stats if enabled
	cacheStats := manager.CacheStats()
	if cacheStats != nil {
		fmt.Println("Cache Statistics")
		fmt.Println("----------------")
		fmt.Printf("  Hits:        %d\n", cacheStats.Hits)
		fmt.Printf("  Misses:      %d\n", cacheStats.Misses)
		fmt.Printf("  Evictions:   %d\n", cacheStats.Evictions)
		fmt.Printf("  Expirations: %d\n", cacheStats.Expirations)
		if cacheStats.Hits+cacheStats.Misses > 0 {
			hitRate := float64(cacheStats.Hits) / float64(cacheStats.Hits+cacheStats.Misses) * 100
			fmt.Printf("  Hit rate:    %.1f%%\n", hitRate)
		}
		fmt.Println()
	}

	return nil
}

func runLLMTest(cmd *cobra.Command, args []string) error {
	prompt := args[0]

	// Load configuration first so we can use log settings
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

	// Initialize logging with config settings
	logLevel := cfg.Settings.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	if verbose {
		logLevel = "debug"
	}
	_ = logger.Init(logLevel, cfg.Settings.LogFile)

	// Ensure LLM is enabled for testing
	if cfg.LLM == nil {
		cfg.LLM = llm.DefaultConfig()
	}
	cfg.LLM.Enabled = true

	// If specific provider requested, only enable that one
	if llmTestProvider != "" {
		pt := llm.ProviderType(llmTestProvider)
		cfg.LLM.ProviderOrder = []llm.ProviderType{pt}
	}

	// Create manager
	manager, err := llm.NewManager(cfg.LLM, providers.DefaultFactories())
	if err != nil {
		return fmt.Errorf("failed to create LLM manager: %w", err)
	}
	defer func() { _ = manager.Close() }()

	// Check available providers
	ctx := context.Background()
	available := manager.AvailableProviders(ctx)
	if len(available) == 0 {
		return fmt.Errorf("no LLM providers available")
	}

	fmt.Printf("Testing with providers: %s\n", formatProviderOrder(available))
	fmt.Printf("Prompt: %s\n\n", prompt)

	// Create analysis request
	req := &llm.AnalysisRequest{
		Type:      llm.AnalysisContextual,
		EventType: "Test",
		ToolName:  "Test",
		ToolInput: map[string]interface{}{
			"prompt": prompt,
		},
	}

	// Set timeout
	ctx, cancel := context.WithTimeout(ctx, time.Duration(llmTestTimeout)*time.Second)
	defer cancel()

	// Run analysis
	fmt.Println("Analyzing...")
	start := time.Now()
	resp, err := manager.Analyze(ctx, req)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	// Display results
	fmt.Println()
	fmt.Println("Results")
	fmt.Println("=======")
	fmt.Printf("Provider:   %s\n", resp.ProviderType)
	fmt.Printf("Decision:   %s\n", resp.Decision)
	fmt.Printf("Confidence: %.2f\n", resp.Confidence)
	fmt.Printf("Latency:    %s\n", resp.Latency.Round(time.Millisecond))
	if resp.TokensUsed > 0 {
		fmt.Printf("Tokens:     %d\n", resp.TokensUsed)
	}
	if resp.CostCents > 0 {
		fmt.Printf("Cost:       %.4f cents\n", resp.CostCents)
	}
	if resp.Cached {
		fmt.Println("(from cache)")
	}
	fmt.Println()
	fmt.Println("Reasoning:")
	fmt.Println(resp.Reasoning)

	if len(resp.Findings) > 0 {
		fmt.Println()
		fmt.Println("Findings:")
		for i, f := range resp.Findings {
			fmt.Printf("  %d. [%s/%s] %s\n", i+1, f.Category, f.Severity, f.Description)
			if f.Evidence != "" {
				fmt.Printf("     Evidence: %s\n", f.Evidence)
			}
		}
	}

	// Output JSON if verbose
	if verbose {
		fmt.Println()
		fmt.Println("Raw Response:")
		jsonBytes, _ := json.MarshalIndent(resp, "", "  ")
		fmt.Println(string(jsonBytes))
	}

	fmt.Printf("\nTotal time: %s\n", time.Since(start).Round(time.Millisecond))
	return nil
}

func formatProviderOrder(providers []llm.ProviderType) string {
	var parts []string
	for _, p := range providers {
		parts = append(parts, string(p))
	}
	return strings.Join(parts, " -> ")
}
