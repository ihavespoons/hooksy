package cli

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/ihavespoons/hooksy/internal/trace"
	"github.com/spf13/cobra"
)

var (
	traceLimit   int
	traceSince   string
	traceClear   bool
	traceJSON    bool
	traceVerbose bool
)

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Manage execution traces",
	Long: `Manage execution traces for session analysis.

Execution traces record events within Claude Code sessions to enable
cross-event pattern detection and behavioral analysis.

Example:
  hooksy trace list             # List all sessions
  hooksy trace show <session>   # Show events for a session
  hooksy trace clear            # Clear all traces`,
}

var traceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List traced sessions",
	Long:  `List all traced sessions with their timestamps and event counts.`,
	RunE:  runTraceList,
}

var traceShowCmd = &cobra.Command{
	Use:   "show <session-id>",
	Short: "Show events for a session",
	Long:  `Show traced events for a specific session.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runTraceShow,
}

var traceClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "Clear trace data",
	Long:  `Clear all traced sessions and events.`,
	RunE:  runTraceClear,
}

var traceAnalyzeCmd = &cobra.Command{
	Use:   "analyze <transcript-path>",
	Short: "Analyze a transcript for suspicious patterns",
	Long: `Analyze a Claude Code transcript file for deceptive behavior patterns.

This command parses the JSONL transcript and looks for:
- Deception indicators (hiding actions, misdirection)
- Monitoring awareness (checking if being watched)
- Obfuscation attempts (encoding, evasion)
- Intent vs action mismatches (saying one thing, doing another)

Example:
  hooksy trace analyze ~/.claude/projects/myproject/transcript.jsonl
  hooksy trace analyze transcript.jsonl --verbose
  hooksy trace analyze transcript.jsonl --json`,
	Args: cobra.ExactArgs(1),
	RunE: runTraceAnalyze,
}

func init() {
	// List flags
	traceListCmd.Flags().IntVarP(&traceLimit, "limit", "n", 20, "Maximum number of sessions to show")

	// Show flags
	traceShowCmd.Flags().IntVarP(&traceLimit, "limit", "n", 50, "Maximum number of events to show")
	traceShowCmd.Flags().StringVar(&traceSince, "since", "", "Show events since time (e.g., '1h', '30m')")

	// Clear flags
	traceClearCmd.Flags().BoolVar(&traceClear, "all", false, "Clear all sessions without confirmation")

	// Analyze flags
	traceAnalyzeCmd.Flags().BoolVar(&traceJSON, "json", false, "Output analysis as JSON")
	traceAnalyzeCmd.Flags().BoolVar(&traceVerbose, "verbose", false, "Show detailed findings")

	traceCmd.AddCommand(traceListCmd)
	traceCmd.AddCommand(traceShowCmd)
	traceCmd.AddCommand(traceClearCmd)
	traceCmd.AddCommand(traceAnalyzeCmd)
	rootCmd.AddCommand(traceCmd)
}

func getTraceStore() (trace.SessionStore, error) {
	// Load config to get storage path
	loader, err := config.NewLoader(projectDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create config loader: %w", err)
	}

	cfg, err := loader.Load()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	store, err := trace.NewSQLiteStore(cfg.Settings.Trace.StoragePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open trace store: %w", err)
	}

	return store, nil
}

func runTraceList(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	store, err := getTraceStore()
	if err != nil {
		return err
	}
	defer store.Close()

	sessions, err := store.ListSessions()
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	if len(sessions) == 0 {
		fmt.Println("No traced sessions found.")
		return nil
	}

	// Limit results
	if traceLimit > 0 && len(sessions) > traceLimit {
		sessions = sessions[:traceLimit]
	}

	fmt.Printf("%-40s  %-20s  %-20s  %s\n", "SESSION ID", "CREATED", "LAST SEEN", "CWD")
	fmt.Println(strings.Repeat("-", 100))

	for _, session := range sessions {
		// Truncate session ID if too long
		sessionID := session.SessionID
		if len(sessionID) > 38 {
			sessionID = sessionID[:35] + "..."
		}

		// Truncate CWD if too long
		cwd := session.Cwd
		if len(cwd) > 30 {
			cwd = "..." + cwd[len(cwd)-27:]
		}

		fmt.Printf("%-40s  %-20s  %-20s  %s\n",
			sessionID,
			session.CreatedAt.Format("2006-01-02 15:04:05"),
			session.LastSeenAt.Format("2006-01-02 15:04:05"),
			cwd,
		)
	}

	if len(sessions) == traceLimit {
		fmt.Printf("\n(Showing first %d sessions. Use --limit to see more.)\n", traceLimit)
	}

	return nil
}

func runTraceShow(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	sessionID := args[0]

	store, err := getTraceStore()
	if err != nil {
		return err
	}
	defer store.Close()

	// Get session info
	session, err := store.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	fmt.Printf("Session: %s\n", session.SessionID)
	fmt.Printf("Created: %s\n", session.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Last Seen: %s\n", session.LastSeenAt.Format(time.RFC3339))
	fmt.Printf("CWD: %s\n", session.Cwd)
	fmt.Println()

	// Parse since duration
	since := time.Time{}
	if traceSince != "" {
		d, err := time.ParseDuration(traceSince)
		if err != nil {
			return fmt.Errorf("invalid duration: %s", traceSince)
		}
		since = time.Now().Add(-d)
	}

	// Get events
	var events []*trace.Event
	if since.IsZero() {
		events, err = store.GetRecentEvents(sessionID, traceLimit)
	} else {
		events, err = store.GetSessionEvents(sessionID, since)
		if len(events) > traceLimit {
			events = events[len(events)-traceLimit:]
		}
	}
	if err != nil {
		return fmt.Errorf("failed to get events: %w", err)
	}

	if len(events) == 0 {
		fmt.Println("No events found.")
		return nil
	}

	fmt.Printf("Events (%d):\n", len(events))
	fmt.Println(strings.Repeat("-", 80))

	for _, event := range events {
		fmt.Printf("[%s] %s: %s",
			event.Timestamp.Format("15:04:05"),
			event.EventType,
			event.ToolName,
		)

		if event.Decision != "" {
			fmt.Printf(" -> %s", event.Decision)
		}

		if event.RuleMatched != "" {
			fmt.Printf(" (rule: %s)", event.RuleMatched)
		}

		fmt.Println()

		// Show tool input summary
		if event.ToolInput != nil {
			if cmd, ok := event.ToolInput["command"].(string); ok {
				fmt.Printf("    command: %s\n", truncateStr(cmd, 60))
			}
			if path, ok := event.ToolInput["file_path"].(string); ok {
				fmt.Printf("    file: %s\n", path)
			}
		}
	}

	return nil
}

func runTraceClear(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	store, err := getTraceStore()
	if err != nil {
		return err
	}
	defer store.Close()

	sessions, err := store.ListSessions()
	if err != nil {
		return fmt.Errorf("failed to list sessions: %w", err)
	}

	if len(sessions) == 0 {
		fmt.Println("No traced sessions to clear.")
		return nil
	}

	if !traceClear {
		fmt.Printf("This will delete %d traced sessions. Use --all to confirm.\n", len(sessions))
		return nil
	}

	// Delete all sessions
	deleted := 0
	for _, session := range sessions {
		if err := store.DeleteSession(session.SessionID); err != nil {
			fmt.Printf("Warning: failed to delete session %s: %v\n", session.SessionID, err)
		} else {
			deleted++
		}
	}

	fmt.Printf("Deleted %d sessions.\n", deleted)
	return nil
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func runTraceAnalyze(cmd *cobra.Command, args []string) error {
	if verbose {
		_ = logger.Init("debug", "")
	} else {
		logger.InitQuiet()
	}

	transcriptPath := args[0]

	analyzer := trace.NewTranscriptAnalyzer()
	analysis, err := analyzer.AnalyzeTranscript(transcriptPath)
	if err != nil {
		return fmt.Errorf("failed to analyze transcript: %w", err)
	}

	if traceJSON {
		// JSON output
		output := map[string]interface{}{
			"path":                   transcriptPath,
			"message_count":          analysis.MessageCount,
			"tool_use_count":         analysis.ToolUseCount,
			"risk_score":             analysis.RiskScore,
			"summary":                analysis.Summary,
			"deception_indicators":   len(analysis.DeceptionIndicators),
			"monitoring_awareness":   len(analysis.MonitoringAwareness),
			"obfuscation_attempts":   len(analysis.ObfuscationAttempts),
			"intent_action_mismatches": len(analysis.IntentActionMismatches),
		}

		if traceVerbose {
			output["deception_details"] = analysis.DeceptionIndicators
			output["monitoring_details"] = analysis.MonitoringAwareness
			output["obfuscation_details"] = analysis.ObfuscationAttempts
			output["mismatch_details"] = analysis.IntentActionMismatches
			output["thinking_blocks"] = len(analysis.ThinkingBlocks)
		}

		jsonBytes, _ := json.MarshalIndent(output, "", "  ")
		fmt.Println(string(jsonBytes))
		return nil
	}

	// Human-readable output
	fmt.Printf("Transcript Analysis: %s\n", transcriptPath)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println()

	// Risk score with color indicator
	riskLevel := "LOW"
	riskColor := ""
	if analysis.RiskScore >= 0.3 {
		riskLevel = "MEDIUM"
		riskColor = "⚠️  "
	}
	if analysis.RiskScore >= 0.6 {
		riskLevel = "HIGH"
		riskColor = "🚨 "
	}
	if analysis.RiskScore >= 0.8 {
		riskLevel = "CRITICAL"
		riskColor = "🛑 "
	}

	fmt.Printf("%sRisk Level: %s (%.0f%%)\n", riskColor, riskLevel, analysis.RiskScore*100)
	fmt.Println()

	// Summary stats
	fmt.Printf("Messages: %d | Tool Uses: %d | Thinking Blocks: %d\n",
		analysis.MessageCount, analysis.ToolUseCount, len(analysis.ThinkingBlocks))
	fmt.Println()

	// Findings summary
	fmt.Println("Findings:")
	fmt.Println(strings.Repeat("-", 40))

	if len(analysis.DeceptionIndicators) > 0 {
		fmt.Printf("  🔴 Deception Indicators: %d\n", len(analysis.DeceptionIndicators))
	}
	if len(analysis.MonitoringAwareness) > 0 {
		fmt.Printf("  🟡 Monitoring Awareness: %d\n", len(analysis.MonitoringAwareness))
	}
	if len(analysis.ObfuscationAttempts) > 0 {
		fmt.Printf("  🔴 Obfuscation Attempts: %d\n", len(analysis.ObfuscationAttempts))
	}
	if len(analysis.IntentActionMismatches) > 0 {
		fmt.Printf("  🔴 Intent-Action Mismatches: %d\n", len(analysis.IntentActionMismatches))
	}

	if len(analysis.DeceptionIndicators) == 0 &&
		len(analysis.MonitoringAwareness) == 0 &&
		len(analysis.ObfuscationAttempts) == 0 &&
		len(analysis.IntentActionMismatches) == 0 {
		fmt.Println("  ✅ No suspicious patterns detected")
	}

	// Verbose details
	if traceVerbose {
		fmt.Println()

		if len(analysis.DeceptionIndicators) > 0 {
			fmt.Println("Deception Indicators:")
			fmt.Println(strings.Repeat("-", 40))
			for i, ind := range analysis.DeceptionIndicators {
				if i >= 5 {
					fmt.Printf("  ... and %d more\n", len(analysis.DeceptionIndicators)-5)
					break
				}
				fmt.Printf("  [%s] %s\n", ind.Severity, truncateStr(ind.MatchedText, 50))
				fmt.Printf("    Context: ...%s...\n", truncateStr(ind.Context, 60))
			}
			fmt.Println()
		}

		if len(analysis.IntentActionMismatches) > 0 {
			fmt.Println("Intent-Action Mismatches:")
			fmt.Println(strings.Repeat("-", 40))
			for i, m := range analysis.IntentActionMismatches {
				if i >= 5 {
					fmt.Printf("  ... and %d more\n", len(analysis.IntentActionMismatches)-5)
					break
				}
				fmt.Printf("  [%s] %s\n", m.Severity, m.Explanation)
				fmt.Printf("    Stated: %s\n", truncateStr(m.StatedIntent, 60))
				fmt.Printf("    Actual: %s\n", m.ActualAction)
			}
			fmt.Println()
		}

		if len(analysis.MonitoringAwareness) > 0 {
			fmt.Println("Monitoring Awareness:")
			fmt.Println(strings.Repeat("-", 40))
			for i, ind := range analysis.MonitoringAwareness {
				if i >= 5 {
					fmt.Printf("  ... and %d more\n", len(analysis.MonitoringAwareness)-5)
					break
				}
				fmt.Printf("  [%s] %s\n", ind.Severity, truncateStr(ind.MatchedText, 50))
			}
			fmt.Println()
		}
	}

	return nil
}
