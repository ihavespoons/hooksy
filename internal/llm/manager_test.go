package llm

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockProvider is a test provider implementation
type mockProvider struct {
	providerType ProviderType
	name         string
	available    bool
	analyzeFunc  func(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error)
	cost         float64
}

func (m *mockProvider) Type() ProviderType                { return m.providerType }
func (m *mockProvider) Name() string                      { return m.name }
func (m *mockProvider) Available(ctx context.Context) bool { return m.available }
func (m *mockProvider) EstimateCost(req *AnalysisRequest) float64 { return m.cost }
func (m *mockProvider) Close() error                      { return nil }

func (m *mockProvider) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	if m.analyzeFunc != nil {
		return m.analyzeFunc(ctx, req)
	}
	return &AnalysisResponse{
		Decision:     DecisionAllow,
		Confidence:   0.9,
		Reasoning:    "mock analysis",
		ProviderType: m.providerType,
	}, nil
}

func mockFactory(pt ProviderType, available bool) ProviderFactory {
	return func(cfg *Config) (Provider, error) {
		return &mockProvider{
			providerType: pt,
			name:         string(pt),
			available:    available,
		}, nil
	}
}

func TestNewManager(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	factories := map[ProviderType]ProviderFactory{
		ProviderClaudeCLI: mockFactory(ProviderClaudeCLI, true),
	}

	manager, err := NewManager(cfg, factories)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer manager.Close()

	if manager == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestNewManager_NilConfig(t *testing.T) {
	manager, err := NewManager(nil, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer manager.Close()

	if manager.cfg == nil {
		t.Error("expected default config to be set")
	}
}

func TestNewManager_InvalidConfig(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Mode:    "invalid",
	}

	_, err := NewManager(cfg, nil)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestManager_Analyze_Disabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = false

	manager, _ := NewManager(cfg, nil)
	defer manager.Close()

	_, err := manager.Analyze(context.Background(), &AnalysisRequest{})
	if !errors.Is(err, ErrDisabled) {
		t.Errorf("expected ErrDisabled, got %v", err)
	}
}

func TestManager_Analyze_NoProviders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true

	manager, _ := NewManager(cfg, nil)
	defer manager.Close()

	_, err := manager.Analyze(context.Background(), &AnalysisRequest{})
	if !errors.Is(err, ErrNoProviders) {
		t.Errorf("expected ErrNoProviders, got %v", err)
	}
}

func TestManager_Analyze_Success(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Cache.Enabled = false

	factories := map[ProviderType]ProviderFactory{
		ProviderClaudeCLI: mockFactory(ProviderClaudeCLI, true),
	}

	manager, _ := NewManager(cfg, factories)
	defer manager.Close()

	resp, err := manager.Analyze(context.Background(), &AnalysisRequest{
		Type:      AnalysisContextual,
		EventType: "PreToolUse",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Decision != DecisionAllow {
		t.Errorf("expected allow decision, got %s", resp.Decision)
	}
	if resp.ProviderType != ProviderClaudeCLI {
		t.Errorf("expected claude_cli provider, got %s", resp.ProviderType)
	}
}

func TestManager_Analyze_Fallback(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Cache.Enabled = false
	cfg.ProviderOrder = []ProviderType{ProviderClaudeCLI, ProviderAnthropic}

	factories := map[ProviderType]ProviderFactory{
		ProviderClaudeCLI: mockFactory(ProviderClaudeCLI, false), // unavailable
		ProviderAnthropic: mockFactory(ProviderAnthropic, true),  // available
	}

	manager, _ := NewManager(cfg, factories)
	defer manager.Close()

	resp, err := manager.Analyze(context.Background(), &AnalysisRequest{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.ProviderType != ProviderAnthropic {
		t.Errorf("expected anthropic provider (fallback), got %s", resp.ProviderType)
	}
}

func TestManager_Analyze_Caching(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Cache.Enabled = true
	cfg.Cache.TTL = 5 * time.Minute

	callCount := 0
	factories := map[ProviderType]ProviderFactory{
		ProviderClaudeCLI: func(cfg *Config) (Provider, error) {
			return &mockProvider{
				providerType: ProviderClaudeCLI,
				available:    true,
				analyzeFunc: func(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
					callCount++
					return &AnalysisResponse{
						Decision:     DecisionAllow,
						Confidence:   0.9,
						ProviderType: ProviderClaudeCLI,
					}, nil
				},
			}, nil
		},
	}

	manager, _ := NewManager(cfg, factories)
	defer manager.Close()

	req := &AnalysisRequest{
		Type:      AnalysisContextual,
		EventType: "PreToolUse",
		ToolName:  "Bash",
	}

	// First call - should hit provider
	resp1, _ := manager.Analyze(context.Background(), req)
	if resp1.Cached {
		t.Error("first call should not be cached")
	}

	// Second call - should hit cache
	resp2, _ := manager.Analyze(context.Background(), req)
	if !resp2.Cached {
		t.Error("second call should be cached")
	}

	if callCount != 1 {
		t.Errorf("expected 1 provider call, got %d", callCount)
	}
}

func TestManager_AvailableProviders(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ProviderOrder = []ProviderType{ProviderClaudeCLI, ProviderAnthropic, ProviderOpenAI}

	factories := map[ProviderType]ProviderFactory{
		ProviderClaudeCLI: mockFactory(ProviderClaudeCLI, true),
		ProviderAnthropic: mockFactory(ProviderAnthropic, false),
		ProviderOpenAI:    mockFactory(ProviderOpenAI, true),
	}

	manager, _ := NewManager(cfg, factories)
	defer manager.Close()

	available := manager.AvailableProviders(context.Background())
	if len(available) != 2 {
		t.Errorf("expected 2 available providers, got %d", len(available))
	}
}

func TestManager_ProviderStatus(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.ProviderOrder = []ProviderType{ProviderClaudeCLI, ProviderAnthropic}

	factories := map[ProviderType]ProviderFactory{
		ProviderClaudeCLI: mockFactory(ProviderClaudeCLI, true),
		ProviderAnthropic: mockFactory(ProviderAnthropic, false),
	}

	manager, _ := NewManager(cfg, factories)
	defer manager.Close()

	status := manager.ProviderStatus(context.Background())

	if !status[ProviderClaudeCLI].Available {
		t.Error("expected claude_cli to be available")
	}
	if status[ProviderAnthropic].Available {
		t.Error("expected anthropic to be unavailable")
	}
}

func TestRateLimiter(t *testing.T) {
	rl := newRateLimiter(60, 5) // 60/min = 1/sec, burst 5

	// Should allow initial burst
	for i := 0; i < 5; i++ {
		if !rl.Allow() {
			t.Errorf("expected to allow request %d in burst", i)
		}
	}

	// Next request should be denied (no tokens left)
	if rl.Allow() {
		t.Error("expected to deny request after burst exhausted")
	}
}

func TestBudgetTracker(t *testing.T) {
	bt := newBudgetTracker(100, 80) // 100 cents limit, warn at 80%

	status := bt.Status()
	if status.SpentCents != 0 {
		t.Errorf("expected 0 spent, got %f", status.SpentCents)
	}
	if status.Exceeded {
		t.Error("budget should not be exceeded initially")
	}

	// Record some spending
	bt.Record(50)
	status = bt.Status()
	if status.SpentCents != 50 {
		t.Errorf("expected 50 spent, got %f", status.SpentCents)
	}

	// Check can afford
	if !bt.CanAfford(49) {
		t.Error("should be able to afford 49 cents")
	}
	if bt.CanAfford(51) {
		t.Error("should not be able to afford 51 cents")
	}

	// Exceed budget
	bt.Record(60)
	if !bt.Exceeded() {
		t.Error("budget should be exceeded")
	}
}
