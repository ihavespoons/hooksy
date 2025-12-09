package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Version information set via ldflags
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

var (
	verbose    bool
	configFile string
	projectDir string
)

var rootCmd = &cobra.Command{
	Use:   "hooksy",
	Short: "Security inspector for Claude Code hooks",
	Long: `Hooksy is a security inspection tool for Claude Code hooks.

It receives hook events from Claude Code, inspects them against configurable
security rules, and returns structured decisions (allow/deny/block) with
detailed reasoning.

Configure rules in:
  - ~/.hooksy/config.yaml (global)
  - .hooksy/config.yaml (project-specific)`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("hooksy %s\n", Version)
		fmt.Printf("  commit: %s\n", Commit)
		fmt.Printf("  built:  %s\n", Date)
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging")
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "c", "", "Override config file path")
	rootCmd.PersistentFlags().StringVarP(&projectDir, "project", "p", "", "Override project directory")

	rootCmd.AddCommand(versionCmd)
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}
