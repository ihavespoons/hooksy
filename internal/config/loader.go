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

// LoadGlobalOnly loads configuration from global config only, ignoring project config.
// This is used for daemon commands where project-specific config should not apply.
func (l *Loader) LoadGlobalOnly() (*Config, error) {
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
			Trace:           mergeTraceSettings(base.Settings.Trace, override.Settings.Trace),
			Daemon:          mergeDaemonSettings(base.Settings.Daemon, override.Settings.Daemon),
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
		Allowlist:     mergeRules(base.Allowlist, override.Allowlist),
		SequenceRules: mergeSequenceRules(base.SequenceRules, override.SequenceRules),
	}

	if override.Version == "" {
		result.Version = base.Version
	}

	// Merge LLM config - override takes precedence if set
	if override.LLM != nil {
		result.LLM = override.LLM
	} else {
		result.LLM = base.LLM
	}

	return result
}

// mergeDaemonSettings merges daemon settings, with override taking precedence for set values
func mergeDaemonSettings(base, override DaemonSettings) DaemonSettings {
	result := base

	// Override Enabled if explicitly set in override config
	// Since we can't distinguish "not set" from "set to false" for bool,
	// we check if any daemon settings are configured in override
	if override.Enabled || override.Port != 0 || override.AutoStart {
		result.Enabled = override.Enabled
		result.AutoStart = override.AutoStart
	}

	if override.Port != 0 {
		result.Port = override.Port
	}

	return result
}

// mergeTraceSettings merges trace settings, with override taking precedence for set values
func mergeTraceSettings(base, override TraceSettings) TraceSettings {
	result := base

	// Override Enabled if explicitly set in override config
	// Since we can't distinguish "not set" from "set to false" for bool,
	// we check if any trace settings are configured in override
	if override.Enabled || override.StoragePath != "" || override.SessionTTL != "" ||
		override.MaxEventsPerSession != 0 || override.CleanupProbability != 0 {
		result.Enabled = override.Enabled
	}

	if override.StoragePath != "" {
		result.StoragePath = override.StoragePath
	}
	if override.SessionTTL != "" {
		result.SessionTTL = override.SessionTTL
	}
	if override.MaxEventsPerSession != 0 {
		result.MaxEventsPerSession = override.MaxEventsPerSession
	}
	if override.CleanupProbability != 0 {
		result.CleanupProbability = override.CleanupProbability
	}

	return result
}

// mergeSequenceRules combines sequence rules from base and override
// Rules with the same name are replaced, new rules are added
func mergeSequenceRules(base, override []SequenceRule) []SequenceRule {
	if len(override) == 0 {
		return base
	}
	if len(base) == 0 {
		return override
	}

	// Create a map for quick lookup
	ruleMap := make(map[string]SequenceRule)
	for _, r := range base {
		ruleMap[r.Name] = r
	}
	for _, r := range override {
		ruleMap[r.Name] = r
	}

	// Convert back to slice
	result := make([]SequenceRule, 0, len(ruleMap))
	for _, r := range ruleMap {
		result = append(result, r)
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
