package llm

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if cfg.Enabled {
		t.Error("expected LLM to be disabled by default")
	}

	if cfg.Mode != ModeHybrid {
		t.Errorf("expected hybrid mode, got %s", cfg.Mode)
	}

	if len(cfg.ProviderOrder) == 0 {
		t.Error("expected non-empty provider order")
	}

	if cfg.ProviderOrder[0] != ProviderClaudeCLI {
		t.Errorf("expected first provider to be claude_cli, got %s", cfg.ProviderOrder[0])
	}
}

func TestConfig_Validate_Disabled(t *testing.T) {
	cfg := &Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Errorf("disabled config should validate without error: %v", err)
	}
}

func TestConfig_Validate_InvalidMode(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Mode = "invalid"

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for invalid mode")
	}
	if configErr, ok := err.(*ConfigError); ok {
		if configErr.Field != "mode" {
			t.Errorf("expected field 'mode', got %s", configErr.Field)
		}
	}
}

func TestConfig_Validate_InvalidProviderType(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ProviderOrder = []ProviderType{"invalid_provider"}

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for invalid provider type")
	}
}

func TestConfig_Validate_InvalidConfidence(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Analysis.MinConfidence = 1.5

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for invalid confidence")
	}
}

func TestConfig_Validate_InvalidTimeout(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Timeouts.CLI = 0

	err := cfg.Validate()
	if err == nil {
		t.Error("expected error for zero CLI timeout")
	}

	cfg.Timeouts.CLI = 60 * time.Second
	cfg.Timeouts.API = 0

	err = cfg.Validate()
	if err == nil {
		t.Error("expected error for zero API timeout")
	}
}

func TestConfig_Validate_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	err := cfg.Validate()
	if err != nil {
		t.Errorf("expected valid config, got error: %v", err)
	}
}

func TestConfigError(t *testing.T) {
	err := &ConfigError{Field: "test", Message: "error message"}
	expected := "llm config error: test: error message"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestModeConstants(t *testing.T) {
	modes := []Mode{ModeSync, ModeAsync, ModeHybrid}
	expected := []string{"sync", "async", "hybrid"}

	for i, mode := range modes {
		if string(mode) != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], mode)
		}
	}
}

func TestProviderTypeConstants(t *testing.T) {
	types := []ProviderType{ProviderClaudeCLI, ProviderAnthropic, ProviderOpenAI, ProviderHuggingFace}
	expected := []string{"claude_cli", "anthropic", "openai", "huggingface"}

	for i, pt := range types {
		if string(pt) != expected[i] {
			t.Errorf("expected %s, got %s", expected[i], pt)
		}
	}
}
