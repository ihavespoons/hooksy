package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/ihavespoons/hooksy/internal/config"
)

var (
	initGlobal bool
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize hooksy configuration",
	Long: `Initialize a hooksy configuration file.

By default, creates a .hooksy/config.yaml in the current directory.
Use --global to create ~/.hooksy/config.yaml instead.`,
	RunE: runInit,
}

func init() {
	initCmd.Flags().BoolVarP(&initGlobal, "global", "g", false, "Create global config in ~/.hooksy/")
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	var configPath string

	if initGlobal {
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
		return fmt.Errorf("config file already exists: %s", configPath)
	}

	// Create directory if needed
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Generate starter config
	cfg := generateStarterConfig()

	// Marshal to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	// Write file
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf("Created config file: %s\n", configPath)
	fmt.Println("\nNext steps:")
	fmt.Println("1. Edit the config file to customize security rules")
	fmt.Println("2. Run 'hooksy generate-hooks' to get Claude Code hook configuration")
	fmt.Println("3. Add the generated hooks to your Claude Code settings")

	return nil
}

func generateStarterConfig() *config.Config {
	return &config.Config{
		Version: "1",
		Settings: config.Settings{
			LogLevel:        "info",
			DefaultDecision: "allow",
		},
		Rules: config.Rules{
			PreToolUse: []config.Rule{
				{
					Name:        "protect-hooksy-config",
					Description: "Prevent agents from modifying hooksy configuration",
					Enabled:     true,
					Priority:    200,
					Conditions: config.Conditions{
						ToolName: `^(Write|Edit|NotebookEdit|mcp__.*__(Write|Edit))$`,
						ToolInput: map[string][]config.PatternMatch{
							"file_path": {
								{Pattern: `\.hooksy/`, Message: "Modification of hooksy configuration is not allowed"},
								{Pattern: `(^|/)hooksy[^/]*\.ya?ml$`, Message: "Modification of hooksy configuration is not allowed"},
							},
						},
					},
					Decision: "deny",
				},
				{
					Name:        "block-dangerous-commands",
					Description: "Block potentially dangerous shell commands",
					Enabled:     true,
					Priority:    100,
					Conditions: config.Conditions{
						ToolName: "^(Bash|mcp__.*__Bash)$",
						ToolInput: map[string][]config.PatternMatch{
							"command": {
								{Pattern: `rm\s+-rf\s+/`, Message: "Recursive deletion from root is blocked"},
								{Pattern: `:()\{\s*:\|:&\s*\};:`, Message: "Fork bombs are not allowed"},
								{Pattern: `curl.*\|.*sh`, Message: "Piping curl to shell is blocked"},
								{Pattern: `wget.*\|.*sh`, Message: "Piping wget to shell is blocked"},
								{Pattern: `>\s*/dev/sd[a-z]`, Message: "Direct disk writes are blocked"},
							},
						},
					},
					Decision: "deny",
				},
				{
					Name:        "block-sensitive-file-access",
					Description: "Prevent access to sensitive files",
					Enabled:     true,
					Priority:    90,
					Conditions: config.Conditions{
						ToolName: "^(Read|Write|Edit|mcp__.*__(Read|Write|Edit))$",
						ToolInput: map[string][]config.PatternMatch{
							"file_path": {
								{Pattern: `\.(env|pem|key|crt|p12|pfx)$`, Message: "Access to secrets/certificates blocked"},
								{Pattern: `/(\.ssh|\.gnupg|\.aws|\.kube)/`, Message: "Access to credential directories blocked"},
								{Pattern: `id_rsa|id_ed25519|id_ecdsa`, Message: "Access to SSH keys blocked"},
							},
						},
					},
					Decision: "deny",
				},
			},
			PostToolUse: []config.Rule{
				{
					Name:        "detect-secret-leakage",
					Description: "Detect if secrets appear in command output",
					Enabled:     true,
					Priority:    100,
					Conditions: config.Conditions{
						ToolResponse: []config.PatternMatch{
							{Pattern: `AKIA[0-9A-Z]{16}`, Message: "AWS access key detected in output"},
							{Pattern: `-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, Message: "Private key detected in output"},
							{Pattern: `ghp_[a-zA-Z0-9]{36}`, Message: "GitHub token detected in output"},
							{Pattern: `sk-[a-zA-Z0-9]{48}`, Message: "OpenAI API key detected in output"},
						},
					},
					Decision:      "block",
					SystemMessage: "Sensitive data was detected in the output. The response has been blocked.",
				},
			},
			UserPromptSubmit: []config.Rule{
				{
					Name:        "detect-injection-attempts",
					Description: "Detect prompt injection attempts",
					Enabled:     false, // Disabled by default as it may have false positives
					Priority:    100,
					Conditions: config.Conditions{
						Prompt: []config.PatternMatch{
							{Pattern: `(?i)ignore (all |previous |prior )?instructions`, Message: "Potential prompt injection detected"},
							{Pattern: `(?i)you are now|pretend (to be|you are)`, Message: "Role manipulation attempt detected"},
						},
					},
					Decision: "ask",
				},
			},
		},
		Allowlist: []config.Rule{
			{
				Name:        "allow-project-configs",
				Description: "Allow access to common project configuration files",
				Enabled:     true,
				Conditions: config.Conditions{
					ToolInput: map[string][]config.PatternMatch{
						"file_path": {
							{Pattern: `package\.json$`},
							{Pattern: `go\.(mod|sum)$`},
							{Pattern: `Cargo\.toml$`},
							{Pattern: `pyproject\.toml$`},
							{Pattern: `\.hooksy/`},
						},
					},
				},
				Decision: "allow",
			},
		},
	}
}
