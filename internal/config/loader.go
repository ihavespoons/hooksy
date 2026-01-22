package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	globalConfigDir  = ".hooksy"
	projectConfigDir = ".hooksy"
	configFileName   = "config.yaml"
)

// Loader handles loading and merging configuration files
type Loader struct {
	globalPath  string
	projectPath string
}

// NewLoader creates a new configuration loader
func NewLoader(projectDir string) (*Loader, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get home directory: %w", err)
	}

	if projectDir == "" {
		projectDir, err = os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to get working directory: %w", err)
		}
	}

	return &Loader{
		globalPath:  filepath.Join(homeDir, globalConfigDir, configFileName),
		projectPath: filepath.Join(projectDir, projectConfigDir, configFileName),
	}, nil
}

// Load loads and merges configuration from all sources
func (l *Loader) Load() (*Config, error) {
	// Start with defaults
	cfg := DefaultConfig()

	// Load global config if exists
	globalCfg, err := l.loadFile(l.globalPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load global config: %w", err)
	}
	if globalCfg != nil {
		cfg = mergeConfigs(cfg, globalCfg)
	}

	// Load project config if exists
	projectCfg, err := l.loadFile(l.projectPath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load project config: %w", err)
	}
	if projectCfg != nil {
		cfg = mergeConfigs(cfg, projectCfg)
	}

	return cfg, nil
}

// LoadFromFile loads configuration from a specific file
func (l *Loader) LoadFromFile(path string) (*Config, error) {
	return l.loadFile(path)
}

func (l *Loader) loadFile(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	return &cfg, nil
}

// mergeConfigs merges two configurations, with override taking precedence
func mergeConfigs(base, override *Config) *Config {
	result := &Config{
		Version: override.Version,
		Settings: Settings{
			LogLevel:        coalesce(override.Settings.LogLevel, base.Settings.LogLevel),
			LogFile:         coalesce(override.Settings.LogFile, base.Settings.LogFile),
			DefaultDecision: coalesce(override.Settings.DefaultDecision, base.Settings.DefaultDecision),
		},
		Rules: Rules{
			PreToolUse:       mergeRules(base.Rules.PreToolUse, override.Rules.PreToolUse),
			PostToolUse:      mergeRules(base.Rules.PostToolUse, override.Rules.PostToolUse),
			UserPromptSubmit: mergeRules(base.Rules.UserPromptSubmit, override.Rules.UserPromptSubmit),
			Stop:             mergeRules(base.Rules.Stop, override.Rules.Stop),
			SubagentStop:     mergeRules(base.Rules.SubagentStop, override.Rules.SubagentStop),
			Notification:     mergeRules(base.Rules.Notification, override.Rules.Notification),
			SessionStart:     mergeRules(base.Rules.SessionStart, override.Rules.SessionStart),
			SessionEnd:       mergeRules(base.Rules.SessionEnd, override.Rules.SessionEnd),
		},
		Allowlist: mergeRules(base.Allowlist, override.Allowlist),
	}

	if override.Version == "" {
		result.Version = base.Version
	}

	return result
}

// mergeRules combines rules from base and override
// Rules with the same name are replaced, new rules are added
func mergeRules(base, override []Rule) []Rule {
	if len(override) == 0 {
		return base
	}
	if len(base) == 0 {
		return override
	}

	// Create a map for quick lookup
	ruleMap := make(map[string]Rule)
	for _, r := range base {
		ruleMap[r.Name] = r
	}
	for _, r := range override {
		ruleMap[r.Name] = r
	}

	// Convert back to slice and sort by priority
	result := make([]Rule, 0, len(ruleMap))
	for _, r := range ruleMap {
		result = append(result, r)
	}

	// Sort by priority (higher first)
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j].Priority > result[i].Priority {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	return result
}

func coalesce(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// GlobalConfigPath returns the path to the global config file
func (l *Loader) GlobalConfigPath() string {
	return l.globalPath
}

// ProjectConfigPath returns the path to the project config file
func (l *Loader) ProjectConfigPath() string {
	return l.projectPath
}

// Exists checks if a config file exists at the given path
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
