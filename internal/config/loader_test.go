package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNewLoader(t *testing.T) {
	loader, err := NewLoader("")
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}
	if loader == nil {
		t.Fatal("NewLoader returned nil")
	}

	// Should have set global and project paths
	if loader.globalPath == "" {
		t.Error("globalPath is empty")
	}
	if loader.projectPath == "" {
		t.Error("projectPath is empty")
	}
}

func TestNewLoader_WithProjectDir(t *testing.T) {
	tmpDir := t.TempDir()

	loader, err := NewLoader(tmpDir)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	expectedProjectPath := filepath.Join(tmpDir, ".hooksy", "config.yaml")
	if loader.projectPath != expectedProjectPath {
		t.Errorf("got projectPath=%q, want %q", loader.projectPath, expectedProjectPath)
	}
}

func TestLoader_GlobalConfigPath(t *testing.T) {
	loader, err := NewLoader("")
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	path := loader.GlobalConfigPath()
	if path == "" {
		t.Error("GlobalConfigPath returned empty string")
	}
	if filepath.Base(path) != "config.yaml" {
		t.Errorf("expected config.yaml, got %s", filepath.Base(path))
	}
}

func TestLoader_ProjectConfigPath(t *testing.T) {
	tmpDir := t.TempDir()
	loader, err := NewLoader(tmpDir)
	if err != nil {
		t.Fatalf("NewLoader failed: %v", err)
	}

	path := loader.ProjectConfigPath()
	expectedPath := filepath.Join(tmpDir, ".hooksy", "config.yaml")
	if path != expectedPath {
		t.Errorf("got %q, want %q", path, expectedPath)
	}
}

func TestLoader_Load_NoConfigFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a loader with a temp home dir that doesn't have config
	loader := &Loader{
		globalPath:  filepath.Join(tmpDir, "global", ".hooksy", "config.yaml"),
		projectPath: filepath.Join(tmpDir, "project", ".hooksy", "config.yaml"),
	}

	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should return default config
	if cfg.Version != "1" {
		t.Errorf("got Version=%q, want \"1\"", cfg.Version)
	}
	if cfg.Settings.DefaultDecision != "allow" {
		t.Errorf("got DefaultDecision=%q, want \"allow\"", cfg.Settings.DefaultDecision)
	}
}

func TestLoader_Load_GlobalOnly(t *testing.T) {
	tmpDir := t.TempDir()

	// Create global config
	globalDir := filepath.Join(tmpDir, "global", ".hooksy")
	if err := os.MkdirAll(globalDir, 0755); err != nil {
		t.Fatal(err)
	}

	globalConfig := `version: "1"
settings:
  log_level: debug
  default_decision: deny
rules:
  PreToolUse:
    - name: global-rule
      enabled: true
      decision: deny
      conditions:
        tool_name: "^Bash$"
`
	if err := os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte(globalConfig), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{
		globalPath:  filepath.Join(globalDir, "config.yaml"),
		projectPath: filepath.Join(tmpDir, "project", ".hooksy", "config.yaml"),
	}

	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Settings.LogLevel != "debug" {
		t.Errorf("got LogLevel=%q, want \"debug\"", cfg.Settings.LogLevel)
	}
	if cfg.Settings.DefaultDecision != "deny" {
		t.Errorf("got DefaultDecision=%q, want \"deny\"", cfg.Settings.DefaultDecision)
	}
	// Should have 2 rules: protect-hooksy-config from default + global-rule
	if len(cfg.Rules.PreToolUse) != 2 {
		t.Errorf("got %d PreToolUse rules, want 2", len(cfg.Rules.PreToolUse))
	}
	// protect-hooksy-config has priority 200, global-rule has no priority (0)
	if cfg.Rules.PreToolUse[0].Name != "protect-hooksy-config" {
		t.Errorf("got first rule name %q, want \"protect-hooksy-config\"", cfg.Rules.PreToolUse[0].Name)
	}
	if cfg.Rules.PreToolUse[1].Name != "global-rule" {
		t.Errorf("got second rule name %q, want \"global-rule\"", cfg.Rules.PreToolUse[1].Name)
	}
}

func TestLoader_Load_ProjectOverridesGlobal(t *testing.T) {
	tmpDir := t.TempDir()

	// Create global config
	globalDir := filepath.Join(tmpDir, "global", ".hooksy")
	if err := os.MkdirAll(globalDir, 0755); err != nil {
		t.Fatal(err)
	}

	globalConfig := `version: "1"
settings:
  log_level: info
  default_decision: allow
rules:
  PreToolUse:
    - name: global-rule
      enabled: true
      priority: 50
      decision: allow
      conditions:
        tool_name: "^Bash$"
`
	if err := os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte(globalConfig), 0644); err != nil {
		t.Fatal(err)
	}

	// Create project config
	projectDir := filepath.Join(tmpDir, "project", ".hooksy")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatal(err)
	}

	projectConfig := `version: "1"
settings:
  log_level: debug
rules:
  PreToolUse:
    - name: project-rule
      enabled: true
      priority: 100
      decision: deny
      conditions:
        tool_name: "^Read$"
`
	if err := os.WriteFile(filepath.Join(projectDir, "config.yaml"), []byte(projectConfig), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{
		globalPath:  filepath.Join(globalDir, "config.yaml"),
		projectPath: filepath.Join(projectDir, "config.yaml"),
	}

	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Project overrides log_level
	if cfg.Settings.LogLevel != "debug" {
		t.Errorf("got LogLevel=%q, want \"debug\"", cfg.Settings.LogLevel)
	}

	// Global default_decision preserved since project didn't specify
	if cfg.Settings.DefaultDecision != "allow" {
		t.Errorf("got DefaultDecision=%q, want \"allow\"", cfg.Settings.DefaultDecision)
	}

	// Should have 3 rules merged: protect-hooksy-config (default) + global-rule + project-rule
	if len(cfg.Rules.PreToolUse) != 3 {
		t.Errorf("got %d PreToolUse rules, want 3", len(cfg.Rules.PreToolUse))
	}

	// Rules sorted by priority: protect-hooksy-config (200), project-rule (100), global-rule (50)
	if cfg.Rules.PreToolUse[0].Name != "protect-hooksy-config" {
		t.Errorf("expected protect-hooksy-config first (priority 200), got %q", cfg.Rules.PreToolUse[0].Name)
	}
	if cfg.Rules.PreToolUse[1].Name != "project-rule" {
		t.Errorf("expected project-rule second (priority 100), got %q", cfg.Rules.PreToolUse[1].Name)
	}
	if cfg.Rules.PreToolUse[2].Name != "global-rule" {
		t.Errorf("expected global-rule third (priority 50), got %q", cfg.Rules.PreToolUse[2].Name)
	}
}

func TestLoader_Load_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()

	globalDir := filepath.Join(tmpDir, ".hooksy")
	if err := os.MkdirAll(globalDir, 0755); err != nil {
		t.Fatal(err)
	}

	invalidYAML := `invalid: yaml: content: [}`
	if err := os.WriteFile(filepath.Join(globalDir, "config.yaml"), []byte(invalidYAML), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{
		globalPath:  filepath.Join(globalDir, "config.yaml"),
		projectPath: filepath.Join(tmpDir, "project", ".hooksy", "config.yaml"),
	}

	_, err := loader.Load()
	if err == nil {
		t.Error("expected error for invalid YAML")
	}
}

func TestLoader_LoadFromFile(t *testing.T) {
	tmpDir := t.TempDir()

	configContent := `version: "1"
settings:
  log_level: warn
  default_decision: ask
rules:
  PostToolUse:
    - name: detect-secrets
      enabled: true
      decision: block
      conditions:
        tool_response:
          - pattern: "password"
            message: "password detected"
`
	configPath := filepath.Join(tmpDir, "custom-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	loader, _ := NewLoader(tmpDir)
	cfg, err := loader.LoadFromFile(configPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if cfg.Settings.LogLevel != "warn" {
		t.Errorf("got LogLevel=%q, want \"warn\"", cfg.Settings.LogLevel)
	}
	if cfg.Settings.DefaultDecision != "ask" {
		t.Errorf("got DefaultDecision=%q, want \"ask\"", cfg.Settings.DefaultDecision)
	}
	if len(cfg.Rules.PostToolUse) != 1 {
		t.Errorf("got %d PostToolUse rules, want 1", len(cfg.Rules.PostToolUse))
	}
}

func TestLoader_LoadFromFile_NotFound(t *testing.T) {
	loader, _ := NewLoader("")
	_, err := loader.LoadFromFile("/nonexistent/config.yaml")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestMergeConfigs(t *testing.T) {
	base := &Config{
		Version: "1",
		Settings: Settings{
			LogLevel:        "info",
			LogFile:         "/var/log/base.log",
			DefaultDecision: "allow",
		},
		Rules: Rules{
			PreToolUse: []Rule{
				{Name: "base-rule", Enabled: true, Priority: 50},
			},
		},
		Allowlist: []Rule{
			{Name: "base-allow", Enabled: true},
		},
	}

	override := &Config{
		Version: "2",
		Settings: Settings{
			LogLevel: "debug",
			// LogFile not set, should keep base
			// DefaultDecision not set, should keep base
		},
		Rules: Rules{
			PreToolUse: []Rule{
				{Name: "override-rule", Enabled: true, Priority: 100},
			},
		},
	}

	result := mergeConfigs(base, override)

	if result.Version != "2" {
		t.Errorf("got Version=%q, want \"2\"", result.Version)
	}
	if result.Settings.LogLevel != "debug" {
		t.Errorf("got LogLevel=%q, want \"debug\"", result.Settings.LogLevel)
	}
	if result.Settings.LogFile != "/var/log/base.log" {
		t.Errorf("got LogFile=%q, want \"/var/log/base.log\"", result.Settings.LogFile)
	}
	if result.Settings.DefaultDecision != "allow" {
		t.Errorf("got DefaultDecision=%q, want \"allow\"", result.Settings.DefaultDecision)
	}

	// Rules should be merged
	if len(result.Rules.PreToolUse) != 2 {
		t.Errorf("got %d PreToolUse rules, want 2", len(result.Rules.PreToolUse))
	}
}

func TestMergeConfigs_EmptyVersion(t *testing.T) {
	base := &Config{Version: "1"}
	override := &Config{Version: ""}

	result := mergeConfigs(base, override)

	if result.Version != "1" {
		t.Errorf("got Version=%q, want \"1\" (base preserved)", result.Version)
	}
}

func TestMergeRules(t *testing.T) {
	base := []Rule{
		{Name: "rule-a", Enabled: true, Priority: 50, Decision: "allow"},
		{Name: "rule-b", Enabled: true, Priority: 30, Decision: "deny"},
	}

	override := []Rule{
		{Name: "rule-a", Enabled: false, Priority: 100, Decision: "deny"},  // Override existing
		{Name: "rule-c", Enabled: true, Priority: 80, Decision: "ask"},     // New rule
	}

	result := mergeRules(base, override)

	if len(result) != 3 {
		t.Errorf("got %d rules, want 3", len(result))
	}

	// Should be sorted by priority descending
	if result[0].Name != "rule-a" || result[0].Priority != 100 {
		t.Errorf("first rule should be rule-a with priority 100, got %s with %d", result[0].Name, result[0].Priority)
	}
	if result[1].Name != "rule-c" || result[1].Priority != 80 {
		t.Errorf("second rule should be rule-c with priority 80, got %s with %d", result[1].Name, result[1].Priority)
	}
	if result[2].Name != "rule-b" || result[2].Priority != 30 {
		t.Errorf("third rule should be rule-b with priority 30, got %s with %d", result[2].Name, result[2].Priority)
	}

	// rule-a should have been overridden
	for _, r := range result {
		if r.Name == "rule-a" {
			if r.Enabled != false {
				t.Error("rule-a should be disabled (overridden)")
			}
			if r.Decision != "deny" {
				t.Error("rule-a should have decision=deny (overridden)")
			}
		}
	}
}

func TestMergeRules_EmptySlices(t *testing.T) {
	base := []Rule{{Name: "base-rule"}}

	// Empty override returns base
	result := mergeRules(base, nil)
	if len(result) != 1 || result[0].Name != "base-rule" {
		t.Error("empty override should return base")
	}

	result = mergeRules(base, []Rule{})
	if len(result) != 1 || result[0].Name != "base-rule" {
		t.Error("empty slice override should return base")
	}

	// Empty base returns override
	override := []Rule{{Name: "override-rule"}}
	result = mergeRules(nil, override)
	if len(result) != 1 || result[0].Name != "override-rule" {
		t.Error("empty base should return override")
	}

	result = mergeRules([]Rule{}, override)
	if len(result) != 1 || result[0].Name != "override-rule" {
		t.Error("empty slice base should return override")
	}
}

func TestCoalesce(t *testing.T) {
	tests := []struct {
		a, b, want string
	}{
		{"value", "default", "value"},
		{"", "default", "default"},
		{"value", "", "value"},
		{"", "", ""},
	}

	for _, tt := range tests {
		got := coalesce(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("coalesce(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestExists(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a file
	existingFile := filepath.Join(tmpDir, "exists.yaml")
	if err := os.WriteFile(existingFile, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	if !Exists(existingFile) {
		t.Error("Exists should return true for existing file")
	}

	nonExistent := filepath.Join(tmpDir, "nonexistent.yaml")
	if Exists(nonExistent) {
		t.Error("Exists should return false for nonexistent file")
	}
}

func TestMergeTraceSettings(t *testing.T) {
	base := TraceSettings{
		Enabled:             false,
		StoragePath:         "/base/path",
		SessionTTL:          "24h",
		MaxEventsPerSession: 1000,
		CleanupProbability:  0.1,
	}

	t.Run("override enabled", func(t *testing.T) {
		override := TraceSettings{
			Enabled: true,
		}
		result := mergeTraceSettings(base, override)
		if !result.Enabled {
			t.Error("Enabled should be true from override")
		}
		if result.StoragePath != "/base/path" {
			t.Errorf("StoragePath should be preserved from base, got %q", result.StoragePath)
		}
	})

	t.Run("override storage path", func(t *testing.T) {
		override := TraceSettings{
			StoragePath: "/override/path",
		}
		result := mergeTraceSettings(base, override)
		if result.StoragePath != "/override/path" {
			t.Errorf("StoragePath should be overridden, got %q", result.StoragePath)
		}
	})

	t.Run("override all fields", func(t *testing.T) {
		override := TraceSettings{
			Enabled:             true,
			StoragePath:         "/new/path",
			SessionTTL:          "48h",
			MaxEventsPerSession: 500,
			CleanupProbability:  0.2,
		}
		result := mergeTraceSettings(base, override)
		if !result.Enabled {
			t.Error("Enabled should be true")
		}
		if result.StoragePath != "/new/path" {
			t.Errorf("StoragePath wrong, got %q", result.StoragePath)
		}
		if result.SessionTTL != "48h" {
			t.Errorf("SessionTTL wrong, got %q", result.SessionTTL)
		}
		if result.MaxEventsPerSession != 500 {
			t.Errorf("MaxEventsPerSession wrong, got %d", result.MaxEventsPerSession)
		}
		if result.CleanupProbability != 0.2 {
			t.Errorf("CleanupProbability wrong, got %f", result.CleanupProbability)
		}
	})

	t.Run("empty override preserves base", func(t *testing.T) {
		override := TraceSettings{}
		result := mergeTraceSettings(base, override)
		if result.Enabled != base.Enabled {
			t.Error("Enabled should be preserved from base")
		}
		if result.StoragePath != base.StoragePath {
			t.Error("StoragePath should be preserved from base")
		}
		if result.SessionTTL != base.SessionTTL {
			t.Error("SessionTTL should be preserved from base")
		}
	})
}

func TestMergeSequenceRules(t *testing.T) {
	base := []SequenceRule{
		{Name: "rule-a", Enabled: true, Decision: "allow"},
		{Name: "rule-b", Enabled: true, Decision: "deny"},
	}

	t.Run("override replaces same-name rule", func(t *testing.T) {
		override := []SequenceRule{
			{Name: "rule-a", Enabled: false, Decision: "deny"},
		}
		result := mergeSequenceRules(base, override)
		if len(result) != 2 {
			t.Errorf("got %d rules, want 2", len(result))
		}
		// Find rule-a and check it was overridden
		for _, r := range result {
			if r.Name == "rule-a" {
				if r.Enabled != false {
					t.Error("rule-a should be disabled (overridden)")
				}
				if r.Decision != "deny" {
					t.Error("rule-a should have decision=deny (overridden)")
				}
			}
		}
	})

	t.Run("new rules are added", func(t *testing.T) {
		override := []SequenceRule{
			{Name: "rule-c", Enabled: true, Decision: "ask"},
		}
		result := mergeSequenceRules(base, override)
		if len(result) != 3 {
			t.Errorf("got %d rules, want 3", len(result))
		}
	})

	t.Run("empty override returns base", func(t *testing.T) {
		result := mergeSequenceRules(base, nil)
		if len(result) != 2 {
			t.Errorf("got %d rules, want 2", len(result))
		}
		result = mergeSequenceRules(base, []SequenceRule{})
		if len(result) != 2 {
			t.Errorf("got %d rules, want 2", len(result))
		}
	})

	t.Run("empty base returns override", func(t *testing.T) {
		override := []SequenceRule{{Name: "only-rule"}}
		result := mergeSequenceRules(nil, override)
		if len(result) != 1 {
			t.Errorf("got %d rules, want 1", len(result))
		}
		result = mergeSequenceRules([]SequenceRule{}, override)
		if len(result) != 1 {
			t.Errorf("got %d rules, want 1", len(result))
		}
	})
}

func TestLoader_Load_TraceSettings(t *testing.T) {
	tmpDir := t.TempDir()

	// Create project config with trace settings
	projectDir := filepath.Join(tmpDir, "project", ".hooksy")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatal(err)
	}

	projectConfig := `version: "1"
settings:
  trace:
    enabled: true
    storage_path: "/custom/path/traces.db"
    session_ttl: "48h"
    max_events_per_session: 500
`
	if err := os.WriteFile(filepath.Join(projectDir, "config.yaml"), []byte(projectConfig), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{
		globalPath:  filepath.Join(tmpDir, "global", ".hooksy", "config.yaml"),
		projectPath: filepath.Join(projectDir, "config.yaml"),
	}

	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if !cfg.Settings.Trace.Enabled {
		t.Error("Trace.Enabled should be true")
	}
	if cfg.Settings.Trace.StoragePath != "/custom/path/traces.db" {
		t.Errorf("Trace.StoragePath wrong, got %q", cfg.Settings.Trace.StoragePath)
	}
	if cfg.Settings.Trace.SessionTTL != "48h" {
		t.Errorf("Trace.SessionTTL wrong, got %q", cfg.Settings.Trace.SessionTTL)
	}
	if cfg.Settings.Trace.MaxEventsPerSession != 500 {
		t.Errorf("Trace.MaxEventsPerSession wrong, got %d", cfg.Settings.Trace.MaxEventsPerSession)
	}
	// CleanupProbability should come from default since not specified
	if cfg.Settings.Trace.CleanupProbability != 0.1 {
		t.Errorf("Trace.CleanupProbability should be default 0.1, got %f", cfg.Settings.Trace.CleanupProbability)
	}
}

func TestLoader_Load_SequenceRules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create project config with sequence rules
	projectDir := filepath.Join(tmpDir, "project", ".hooksy")
	if err := os.MkdirAll(projectDir, 0755); err != nil {
		t.Fatal(err)
	}

	projectConfig := `version: "1"
sequence_rules:
  - name: test-sequence
    enabled: true
    window: "5m"
    decision: deny
    events:
      - event_type: PreToolUse
        tool_name: "^Bash$"
`
	if err := os.WriteFile(filepath.Join(projectDir, "config.yaml"), []byte(projectConfig), 0644); err != nil {
		t.Fatal(err)
	}

	loader := &Loader{
		globalPath:  filepath.Join(tmpDir, "global", ".hooksy", "config.yaml"),
		projectPath: filepath.Join(projectDir, "config.yaml"),
	}

	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if len(cfg.SequenceRules) != 1 {
		t.Errorf("got %d sequence rules, want 1", len(cfg.SequenceRules))
	}
	if cfg.SequenceRules[0].Name != "test-sequence" {
		t.Errorf("sequence rule name wrong, got %q", cfg.SequenceRules[0].Name)
	}
	if cfg.SequenceRules[0].Window != "5m" {
		t.Errorf("sequence rule window wrong, got %q", cfg.SequenceRules[0].Window)
	}
}
