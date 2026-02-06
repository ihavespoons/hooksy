package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/daemon"
	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/ihavespoons/hooksy/internal/trace"
	"github.com/spf13/cobra"
)

var (
	backgroundFlag      bool
	backgroundChildFlag bool
)

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Manage the hooksy dashboard daemon",
	Long: `Manage the hooksy dashboard daemon.

The daemon provides a real-time web dashboard for monitoring hook events,
viewing session activity, and tracking rule violations.

Enable the daemon in your config:
  settings:
    daemon:
      enabled: true
      port: 8741
      auto_start: true

Commands:
  start  - Start the daemon (foreground or background)
  stop   - Stop the running daemon
  status - Check if the daemon is running`,
}

var daemonStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the dashboard daemon",
	Long: `Start the hooksy dashboard daemon.

By default, runs in the foreground. Use --background to run as a background process.

Example:
  hooksy daemon start              # Run in foreground
  hooksy daemon start --background # Run in background`,
	RunE: runDaemonStart,
}

var daemonStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the running daemon",
	Long: `Stop the hooksy dashboard daemon if it is running.

Example:
  hooksy daemon stop`,
	RunE: runDaemonStop,
}

var daemonStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check daemon status",
	Long: `Check if the hooksy dashboard daemon is running.

Example:
  hooksy daemon status`,
	RunE: runDaemonStatus,
}

func init() {
	daemonStartCmd.Flags().BoolVarP(&backgroundFlag, "background", "b", false, "Run daemon in background")
	daemonStartCmd.Flags().BoolVar(&backgroundChildFlag, "background-child", false, "Internal flag for background process")
	_ = daemonStartCmd.Flags().MarkHidden("background-child")

	daemonCmd.AddCommand(daemonStartCmd)
	daemonCmd.AddCommand(daemonStopCmd)
	daemonCmd.AddCommand(daemonStatusCmd)
	rootCmd.AddCommand(daemonCmd)
}

func runDaemonStart(cmd *cobra.Command, args []string) error {
	// Load configuration - daemon only uses global config to avoid project-specific conflicts
	loader, err := config.NewLoader("")
	if err != nil {
		return fmt.Errorf("failed to create config loader: %w", err)
	}

	var cfg *config.Config
	if configFile != "" {
		cfg, err = loader.LoadFromFile(configFile)
	} else {
		cfg, err = loader.LoadGlobalOnly()
	}
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Initialize logging
	if verbose {
		_ = logger.Init("debug", cfg.Settings.LogFile)
	} else if cfg.Settings.LogLevel != "" {
		_ = logger.Init(cfg.Settings.LogLevel, cfg.Settings.LogFile)
	} else {
		_ = logger.Init("info", cfg.Settings.LogFile)
	}

	lifecycle := daemon.NewLifecycle(cfg.Settings.Daemon)

	// If --background flag is set, start in background and exit
	if backgroundFlag && !backgroundChildFlag {
		if lifecycle.IsRunning() {
			fmt.Println("Daemon is already running")
			return nil
		}

		if err := lifecycle.StartInBackground(); err != nil {
			return fmt.Errorf("failed to start daemon in background: %w", err)
		}

		fmt.Printf("Daemon started on http://127.0.0.1:%d\n", lifecycle.Port())
		return nil
	}

	// Check if already running (for foreground mode)
	if !backgroundChildFlag && lifecycle.IsRunning() {
		return fmt.Errorf("daemon is already running (PID file: %s)", lifecycle.PIDFile())
	}

	// Initialize trace store - the daemon always needs access to the trace DB
	// to serve dashboard data, regardless of the trace.enabled setting
	// (which controls whether the inspect command writes events)
	storagePath := cfg.Settings.Trace.StoragePath
	store, storeErr := trace.NewSQLiteStore(storagePath)
	if storeErr != nil {
		logger.Warn().Err(storeErr).Msg("Failed to initialize trace store, running without data")
	}

	// Create and start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := daemon.NewServer(cfg, store, Version)

	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	if !backgroundChildFlag {
		fmt.Printf("Dashboard running at http://127.0.0.1:%d\n", server.Port())
		fmt.Println("Press Ctrl+C to stop")
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5000000000)
	defer shutdownCancel()

	if err := server.Stop(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("Error during shutdown")
	}

	if store != nil {
		_ = store.Close()
	}

	return nil
}

func runDaemonStop(cmd *cobra.Command, args []string) error {
	// Load configuration - daemon only uses global config
	loader, err := config.NewLoader("")
	if err != nil {
		return fmt.Errorf("failed to create config loader: %w", err)
	}

	var cfg *config.Config
	if configFile != "" {
		cfg, err = loader.LoadFromFile(configFile)
	} else {
		cfg, err = loader.LoadGlobalOnly()
	}
	if err != nil {
		cfg = config.DefaultConfig()
	}

	lifecycle := daemon.NewLifecycle(cfg.Settings.Daemon)

	if !lifecycle.IsRunning() {
		fmt.Println("Daemon is not running")
		return nil
	}

	pid, _ := lifecycle.GetPID()
	if err := lifecycle.Stop(); err != nil {
		return fmt.Errorf("failed to stop daemon: %w", err)
	}

	fmt.Printf("Daemon stopped (was PID %d)\n", pid)
	return nil
}

func runDaemonStatus(cmd *cobra.Command, args []string) error {
	// Load configuration - daemon only uses global config
	loader, err := config.NewLoader("")
	if err != nil {
		return fmt.Errorf("failed to create config loader: %w", err)
	}

	var cfg *config.Config
	if configFile != "" {
		cfg, err = loader.LoadFromFile(configFile)
	} else {
		cfg, err = loader.LoadGlobalOnly()
	}
	if err != nil {
		cfg = config.DefaultConfig()
	}

	lifecycle := daemon.NewLifecycle(cfg.Settings.Daemon)

	if lifecycle.IsRunning() {
		pid, _ := lifecycle.GetPID()
		fmt.Printf("Daemon is running (PID %d)\n", pid)
		fmt.Printf("Dashboard: http://127.0.0.1:%d\n", lifecycle.Port())
	} else {
		fmt.Println("Daemon is not running")
	}

	return nil
}
