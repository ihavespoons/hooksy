package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/ctvp"
	"github.com/ihavespoons/hooksy/internal/engine"
	"github.com/ihavespoons/hooksy/internal/llm"
	"github.com/ihavespoons/hooksy/internal/llm/providers"
	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/spf13/cobra"
)

var (
	ctvpJSON    bool
	ctvpVerbose bool
)

var ctvpCmd = &cobra.Command{
	Use:   "ctvp",
	Short: "Cross-Trace Verification Protocol analysis",
	Long: `Cross-Trace Verification Protocol (CTVP) for detecting backdoors
in code-generating LLMs by analyzing execution trace prediction consistency.

Based on arXiv 2512.13821 - backdoored models show inconsistent trace predictions
across semantically equivalent code variants, while benign models remain consistent.

Example:
  hooksy ctvp analyze script.sh    # Analyze a shell script
  hooksy ctvp status               # Show CTVP statistics
  hooksy ctvp threshold            # Show current thresholds
  hooksy ctvp history              # Show recent analyses`,
}

var ctvpAnalyzeCmd = &cobra.Command{
	Use:   "analyze <file>",
	Short: "Run CTVP analysis on a code file",
	Long: `Run CTVP analysis on a code file to detect potential backdoor behavior.

The analysis:
1. Generates semantically equivalent code variants
2. Predicts execution traces for each variant using an LLM
3. Compares traces for consistency
4. Reports anomalies that may indicate backdoor triggers

Example:
  hooksy ctvp analyze script.sh
  hooksy ctvp analyze script.py --json
  hooksy ctvp analyze deploy.sh --verbose`,
	Args: cobra.ExactArgs(1),
	RunE: runCTVPAnalyze,
}

var ctvpStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show CTVP statistics",
	Long:  `Show statistics about CTVP analyses performed.`,
	RunE:  runCTVPStatus,
}

var ctvpThresholdCmd = &cobra.Command{
	Use:   "threshold",
	Short: "Show current adaptive thresholds",
	Long: `Show current CTVP decision thresholds.

Thresholds determine how aggregate consistency scores map to decisions:
- Scores below deny_threshold result in DENY
- Scores between deny and ask_threshold result in ASK
- Scores above ask_threshold result in ALLOW

With adaptive thresholds enabled, these values adjust based on feedback.`,
	RunE: runCTVPThreshold,
}

var ctvpHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "Show recent CTVP analyses",
	Long:  `Show recent CTVP analysis results.`,
	RunE:  runCTVPHistory,
}

var ctvpResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset CTVP thresholds to defaults",
	Long:  `Reset adaptive thresholds to their configured defaults.`,
	RunE:  runCTVPReset,
}

func init() {
	// Analyze flags
	ctvpAnalyzeCmd.Flags().BoolVar(&ctvpJSON, "json", false, "Output analysis as JSON")
	ctvpAnalyzeCmd.Flags().BoolVarP(&ctvpVerbose, "verbose", "v", false, "Show detailed output including traces")

	// Status flags
	ctvpStatusCmd.Flags().BoolVar(&ctvpJSON, "json", false, "Output as JSON")

	// Threshold flags
	ctvpThresholdCmd.Flags().BoolVar(&ctvpJSON, "json", false, "Output as JSON")

	// History flags
	ctvpHistoryCmd.Flags().IntVarP(&traceLimit, "limit", "n", 10, "Maximum number of results to show")
	ctvpHistoryCmd.Flags().BoolVar(&ctvpJSON, "json", false, "Output as JSON")

	ctvpCmd.AddCommand(ctvpAnalyzeCmd)
	ctvpCmd.AddCommand(ctvpStatusCmd)
	ctvpCmd.AddCommand(ctvpThresholdCmd)
	ctvpCmd.AddCommand(ctvpHistoryCmd)
	ctvpCmd.AddCommand(ctvpResetCmd)
	rootCmd.AddCommand(ctvpCmd)
}

func getCTVPAnalyzer() (*ctvp.Analyzer, *config.Config, error) {
	// Load config
	loader, err := config.NewLoader(projectDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create config loader: %w", err)
	}

	cfg, err := loader.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Ensure CTVP is configured
	if cfg.CTVP == nil {
		cfg.CTVP = ctvp.DefaultConfig()
	}

	// Enable CTVP for this analysis
	cfg.CTVP.Enabled = true

	// Create LLM manager
	if cfg.LLM == nil {
		cfg.LLM = llm.DefaultConfig()
	}
	cfg.LLM.Enabled = true // Enable LLM for CTVP analysis

	llmManager, err := llm.NewManager(cfg.LLM, providers.DefaultFactories())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create LLM manager: %w", err)
	}

	// Create CTVP analyzer
	adapter := engine.NewLLMClientAdapter(llmManager)
	analyzer := ctvp.NewAnalyzer(cfg.CTVP, adapter)

	return analyzer, cfg, nil
}

func runCTVPAnalyze(cmd *cobra.Command, args []string) error {
	if verbose || ctvpVerbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	filePath := args[0]

	// Read the file
	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	code := string(content)

	if len(code) == 0 {
		return fmt.Errorf("file is empty")
	}

	// Get analyzer
	analyzer, _, err := getCTVPAnalyzer()
	if err != nil {
		return err
	}

	// Determine tool name from file extension
	toolName := "Write"
	if strings.HasSuffix(filePath, ".sh") || strings.HasSuffix(filePath, ".bash") {
		toolName = "Bash"
	}

	fmt.Printf("Analyzing %s...\n\n", filePath)

	// Run analysis
	ctx := context.Background()
	result, err := analyzer.Analyze(ctx, code, toolName)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}

	if ctvpJSON {
		// JSON output
		output, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	// Human-readable output
	fmt.Printf("CTVP Analysis Results\n")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Decision with indicator
	decisionIcon := map[ctvp.CTVPDecision]string{
		ctvp.DecisionAllow: "✅",
		ctvp.DecisionAsk:   "⚠️",
		ctvp.DecisionDeny:  "🔴",
		ctvp.DecisionBlock: "🛑",
	}
	fmt.Printf("%s Decision: %s\n", decisionIcon[result.Decision], strings.ToUpper(string(result.Decision)))
	fmt.Printf("   Score: %.2f\n", result.AggregateScore)
	fmt.Printf("   Variants: %d\n", len(result.Variants))
	fmt.Printf("   Anomalies: %d\n", len(result.Anomalies))
	fmt.Printf("   Duration: %v\n", result.AnalysisTime)
	fmt.Println()

	// Show anomalies
	if len(result.Anomalies) > 0 {
		fmt.Println("Detected Anomalies:")
		fmt.Println(strings.Repeat("-", 40))
		for i, anomaly := range result.Anomalies {
			if i >= 5 && !ctvpVerbose {
				fmt.Printf("  ... and %d more (use --verbose to see all)\n", len(result.Anomalies)-5)
				break
			}
			severityIcon := "⚪"
			if anomaly.Severity >= 0.5 {
				severityIcon = "🟡"
			}
			if anomaly.Severity >= 0.7 {
				severityIcon = "🟠"
			}
			if anomaly.Severity >= 0.9 {
				severityIcon = "🔴"
			}
			fmt.Printf("  %s [%.1f] %s: %s\n", severityIcon, anomaly.Severity, anomaly.AnomalyType, anomaly.Description)
		}
		fmt.Println()
	}

	// Show pairwise scores if verbose
	if ctvpVerbose && len(result.PairwiseScores) > 0 {
		fmt.Println("Pairwise Scores:")
		fmt.Println(strings.Repeat("-", 40))
		for key, score := range result.PairwiseScores {
			fmt.Printf("  %s: %.3f\n", key, score)
		}
		fmt.Println()
	}

	// Show variants if verbose
	if ctvpVerbose && len(result.Variants) > 0 {
		fmt.Println("Code Variants:")
		fmt.Println(strings.Repeat("-", 40))
		for i, variant := range result.Variants {
			fmt.Printf("  [%d] %s (%s)\n", i+1, variant.ID[:8], variant.TransformType)
			if variant.TransformDetails != nil {
				for k, v := range variant.TransformDetails {
					fmt.Printf("      %s: %s\n", k, truncateStr(v, 50))
				}
			}
		}
		fmt.Println()
	}

	// Show reasoning
	fmt.Println("Reasoning:")
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println(result.Reasoning)

	return nil
}

func runCTVPStatus(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	analyzer, _, err := getCTVPAnalyzer()
	if err != nil {
		return err
	}

	metrics := analyzer.GetMetrics()

	if ctvpJSON {
		output, _ := json.MarshalIndent(metrics, "", "  ")
		fmt.Println(string(output))
		return nil
	}

	fmt.Println("CTVP Statistics")
	fmt.Println(strings.Repeat("=", 40))
	fmt.Println()
	fmt.Printf("Total Analyses: %d\n", metrics.TotalAnalyses)
	fmt.Printf("Average Score: %.3f\n", metrics.AverageScore)
	fmt.Printf("Average Duration: %v\n", metrics.AverageAnalysisTime)
	fmt.Printf("Cache Hit Rate: %.1f%%\n", metrics.CacheHitRate*100)
	fmt.Printf("Error Rate: %.1f%%\n", metrics.ErrorRate*100)
	fmt.Println()

	if len(metrics.DecisionCounts) > 0 {
		fmt.Println("Decision Distribution:")
		for decision, count := range metrics.DecisionCounts {
			fmt.Printf("  %s: %d\n", decision, count)
		}
	}

	fmt.Printf("\nLast Reset: %s\n", metrics.LastReset.Format("2006-01-02 15:04:05"))

	return nil
}

func runCTVPThreshold(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	analyzer, cfg, err := getCTVPAnalyzer()
	if err != nil {
		return err
	}

	state := analyzer.GetThresholdState()

	if ctvpJSON {
		output := map[string]interface{}{
			"current":    state,
			"configured": cfg.CTVP.Threshold,
		}
		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(jsonBytes))
		return nil
	}

	fmt.Println("CTVP Thresholds")
	fmt.Println(strings.Repeat("=", 40))
	fmt.Println()
	fmt.Println("Current Thresholds:")
	fmt.Printf("  Deny:  %.3f (scores below this -> DENY)\n", state.DenyThreshold)
	fmt.Printf("  Ask:   %.3f (scores below this -> ASK)\n", state.AskThreshold)
	fmt.Println()

	fmt.Println("Configured Defaults:")
	fmt.Printf("  Deny:  %.3f\n", cfg.CTVP.Threshold.DenyThreshold)
	fmt.Printf("  Ask:   %.3f\n", cfg.CTVP.Threshold.AskThreshold)
	fmt.Println()

	fmt.Println("Adaptive Threshold State:")
	fmt.Printf("  Adaptive: %v\n", cfg.CTVP.Threshold.Adaptive)
	fmt.Printf("  Target FPR: %.2f%%\n", cfg.CTVP.Threshold.TargetFPR*100)
	fmt.Printf("  Sample Count: %d\n", state.SampleCount)
	fmt.Printf("  Est. FPR: %.2f%%\n", state.FalsePositiveRate*100)
	fmt.Printf("  Est. TPR: %.2f%%\n", state.TruePositiveRate*100)
	fmt.Printf("  Last Updated: %s\n", state.LastUpdated.Format("2006-01-02 15:04:05"))

	return nil
}

func runCTVPHistory(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	// This would need session store access
	// For now, show a placeholder message
	fmt.Println("CTVP analysis history requires trace storage to be enabled.")
	fmt.Println("Enable tracing in your config:")
	fmt.Println()
	fmt.Println("settings:")
	fmt.Println("  trace:")
	fmt.Println("    enabled: true")
	fmt.Println()
	fmt.Println("Then use 'hooksy trace show <session-id>' to view CTVP results.")

	return nil
}

func runCTVPReset(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	analyzer, _, err := getCTVPAnalyzer()
	if err != nil {
		return err
	}

	analyzer.ResetThresholds()
	fmt.Println("CTVP thresholds reset to configured defaults.")

	return nil
}
