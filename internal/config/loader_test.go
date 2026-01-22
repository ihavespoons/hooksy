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
	if len(cfg.Rules.PreToolUse) != 1 {
		t.Errorf("got %d PreToolUse rules, want 1", len(cfg.Rules.PreToolUse))
	}
	if cfg.Rules.PreToolUse[0].Name != "global-rule" {
		t.Errorf("got rule name %q, want \"global-rule\"", cfg.Rules.PreToolUse[0].Name)
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

	// Should have both rules merged
	if len(cfg.Rules.PreToolUse) != 2 {
		t.Errorf("got %d PreToolUse rules, want 2", len(cfg.Rules.PreToolUse))
	}

	// Higher priority rule should be first
	if cfg.Rules.PreToolUse[0].Name != "project-rule" {
		t.Errorf("expected project-rule first (higher priority), got %q", cfg.Rules.PreToolUse[0].Name)
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
