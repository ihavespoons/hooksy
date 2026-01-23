package ctvp

import (
	"context"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("CTVP should be disabled by default")
	}

	if cfg.Orbit.Size != 5 {
		t.Errorf("Expected orbit size 5, got %d", cfg.Orbit.Size)
	}

	if cfg.Orbit.MinSize != 3 {
		t.Errorf("Expected min size 3, got %d", cfg.Orbit.MinSize)
	}

	if len(cfg.Orbit.Transformations) != 5 {
		t.Errorf("Expected 5 transformations, got %d", len(cfg.Orbit.Transformations))
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("Default config should be valid, got error: %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{
			name:    "valid default config",
			modify:  func(c *Config) { c.Enabled = true },
			wantErr: false,
		},
		{
			name: "invalid mode",
			modify: func(c *Config) {
				c.Enabled = true
				c.Mode = "invalid"
			},
			wantErr: true,
		},
		{
			name: "orbit size too small",
			modify: func(c *Config) {
				c.Enabled = true
				c.Orbit.Size = 1
			},
			wantErr: true,
		},
		{
			name: "min size greater than size",
			modify: func(c *Config) {
				c.Enabled = true
				c.Orbit.MinSize = 10
			},
			wantErr: true,
		},
		{
			name: "invalid threshold order",
			modify: func(c *Config) {
				c.Enabled = true
				c.Threshold.DenyThreshold = 0.7
				c.Threshold.AskThreshold = 0.3
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tt.modify(cfg)

			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTransformerRegistry(t *testing.T) {
	registry := NewTransformerRegistry()

	// Test all default transformers are registered
	transformTypes := AllTransformations()
	for _, tt := range transformTypes {
		transformer, ok := registry.Get(tt)
		if !ok {
			t.Errorf("Transformer %s not registered", tt)
			continue
		}
		if transformer.Type() != tt {
			t.Errorf("Transformer type mismatch: got %s, want %s", transformer.Type(), tt)
		}
	}
}

func TestVariableRenameTransformer(t *testing.T) {
	transformer := &VariableRenameTransformer{}

	code := `x = 5
y = 10
result = x + y`

	if !transformer.CanTransform(code) {
		t.Error("Should be able to transform code with variables")
	}

	transformed, details, err := transformer.Transform(code)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	if transformed == code {
		t.Error("Transform should produce different code")
	}

	if len(details) == 0 {
		t.Error("Transform should provide details about renames")
	}
}

func TestDeadCodeTransformer(t *testing.T) {
	transformer := &DeadCodeTransformer{}

	tests := []struct {
		name string
		code string
	}{
		{"shell", "#!/bin/bash\necho hello"},
		{"python", "def main():\n    print('hello')"},
		{"go", "package main\nfunc main() {}"},
		{"javascript", "const x = 5;\nconsole.log(x);"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !transformer.CanTransform(tt.code) {
				t.Error("Should be able to transform code")
			}

			transformed, details, err := transformer.Transform(tt.code)
			if err != nil {
				t.Fatalf("Transform failed: %v", err)
			}

			if transformed == tt.code {
				t.Error("Transform should inject dead code")
			}

			if details["injected"] == "" {
				t.Error("Should indicate what was injected")
			}
		})
	}
}

func TestReformatTransformer(t *testing.T) {
	transformer := &ReformatTransformer{}

	code := "x = 5\r\ny = 10\n\n\nz = 15   "

	transformed, details, err := transformer.Transform(code)
	if err != nil {
		t.Fatalf("Transform failed: %v", err)
	}

	if transformed == code {
		t.Error("Transform should reformat code")
	}

	if details["changes"] == "" {
		t.Error("Should indicate what changes were made")
	}
}

func TestOrbitGeneration(t *testing.T) {
	cfg := &OrbitConfig{
		Size:    5,
		MinSize: 3,
		Transformations: []TransformationType{
			TransformVariableRename,
			TransformReformat,
			TransformCommentModify,
		},
		MaxTransformAttempts: 3,
	}

	generator := NewOrbitGenerator(cfg)

	code := `x = 5
y = 10
result = x + y
print(result)`

	orbit, err := generator.Generate(code)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if len(orbit.Variants) < cfg.MinSize {
		t.Errorf("Expected at least %d variants, got %d", cfg.MinSize, len(orbit.Variants))
	}

	// First variant should be original
	if orbit.Variants[0].TransformedCode != code {
		t.Error("First variant should be original code")
	}

	// Other variants should be different
	for i := 1; i < len(orbit.Variants); i++ {
		if orbit.Variants[i].TransformedCode == code {
			t.Errorf("Variant %d should be transformed", i)
		}
	}
}

func TestSimilarityCalculation(t *testing.T) {
	cfg := &SimilarityConfig{
		Metric:              "hybrid",
		StepAlignmentWeight: 0.4,
		StateMatchWeight:    0.4,
		OutputMatchWeight:   0.2,
	}

	calc := NewSimilarityCalculator(cfg)

	// Test identical traces
	trace1 := &ExecutionTrace{
		VariantID: "a",
		Steps: []TraceStep{
			{Line: 1, Operation: "assign", Variables: map[string]interface{}{"x": 5}},
			{Line: 2, Operation: "assign", Variables: map[string]interface{}{"y": 10}},
		},
		FinalState: TraceState{
			Variables: map[string]interface{}{"x": 5, "y": 10, "result": 15},
			Outputs:   []string{"15"},
		},
		Confidence: 0.9,
	}

	trace2 := &ExecutionTrace{
		VariantID: "b",
		Steps: []TraceStep{
			{Line: 1, Operation: "assign", Variables: map[string]interface{}{"x": 5}},
			{Line: 2, Operation: "assign", Variables: map[string]interface{}{"y": 10}},
		},
		FinalState: TraceState{
			Variables: map[string]interface{}{"x": 5, "y": 10, "result": 15},
			Outputs:   []string{"15"},
		},
		Confidence: 0.9,
	}

	result := calc.ComputeSimilarity(trace1, trace2)
	if result.Score < 0.9 {
		t.Errorf("Identical traces should have high similarity, got %.2f", result.Score)
	}

	// Test different traces
	trace3 := &ExecutionTrace{
		VariantID: "c",
		Steps: []TraceStep{
			{Line: 1, Operation: "network_call", SideEffects: []string{"curl evil.com"}},
		},
		FinalState: TraceState{
			Outputs: []string{"malicious output"},
		},
		Confidence: 0.9,
	}

	result2 := calc.ComputeSimilarity(trace1, trace3)
	if result2.Score > 0.5 {
		t.Errorf("Different traces should have low similarity, got %.2f", result2.Score)
	}
}

func TestScoring(t *testing.T) {
	cfg := &ThresholdConfig{
		DenyThreshold: 0.3,
		AskThreshold:  0.5,
	}

	scorer := NewScorer(cfg)

	tests := []struct {
		name     string
		score    float64
		anomalies []TraceAnomaly
		expected CTVPDecision
	}{
		{
			name:     "high score allows",
			score:    0.8,
			anomalies: nil,
			expected: DecisionAllow,
		},
		{
			name:     "medium score asks",
			score:    0.4,
			anomalies: nil,
			expected: DecisionAsk,
		},
		{
			name:     "low score denies",
			score:    0.2,
			anomalies: nil,
			expected: DecisionDeny,
		},
		{
			name:  "critical anomaly blocks",
			score: 0.6,
			anomalies: []TraceAnomaly{
				{Severity: 0.95, AnomalyType: "critical", Description: "Critical issue"},
			},
			expected: DecisionBlock,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, _ := scorer.MakeDecision(tt.score, tt.anomalies)
			if decision != tt.expected {
				t.Errorf("Expected decision %s, got %s", tt.expected, decision)
			}
		})
	}
}

func TestThresholdManager(t *testing.T) {
	cfg := &ThresholdConfig{
		DenyThreshold:  0.3,
		AskThreshold:   0.5,
		Adaptive:       true,
		TargetFPR:      0.05,
		MinSamples:     10,
		AdaptationRate: 0.1,
	}

	tm := NewThresholdManager(cfg, "")

	// Initial thresholds should match config
	deny, ask := tm.GetThresholds()
	if deny != cfg.DenyThreshold {
		t.Errorf("Expected deny threshold %.2f, got %.2f", cfg.DenyThreshold, deny)
	}
	if ask != cfg.AskThreshold {
		t.Errorf("Expected ask threshold %.2f, got %.2f", cfg.AskThreshold, ask)
	}

	// Test state retrieval
	state := tm.GetState()
	if state == nil {
		t.Fatal("State should not be nil")
	}

	// Test reset
	tm.Reset()
	deny2, ask2 := tm.GetThresholds()
	if deny2 != cfg.DenyThreshold || ask2 != cfg.AskThreshold {
		t.Error("Reset should restore default thresholds")
	}
}

func TestMockLLMClient(t *testing.T) {
	mockResponse := `{
		"steps": [
			{"line": 1, "operation": "assign", "variables": {"x": 5}, "side_effects": []}
		],
		"final_state": {"variables": {"x": 5}, "outputs": [], "errors": []},
		"confidence": 0.9
	}`

	client := &MockLLMClient{Response: mockResponse}

	ctx := context.Background()
	resp, err := client.Complete(ctx, "system", "user")
	if err != nil {
		t.Fatalf("Complete failed: %v", err)
	}

	if resp != mockResponse {
		t.Error("Response should match mock")
	}
}

func TestTracePredictor(t *testing.T) {
	mockResponse := `{
		"steps": [
			{"line": 1, "operation": "assign x = 5", "variables": {"x": 5}, "side_effects": []},
			{"line": 2, "operation": "print x", "variables": {"x": 5}, "side_effects": ["stdout: 5"]}
		],
		"final_state": {"variables": {"x": 5}, "outputs": ["5"], "errors": []},
		"confidence": 0.85
	}`

	client := &MockLLMClient{Response: mockResponse}
	cfg := &TraceConfig{
		MaxSteps:           20,
		Parallel:           false,
		MaxParallel:        3,
		IncludeVariables:   true,
		IncludeSideEffects: true,
	}

	predictor := NewTracePredictor(cfg, client)

	variant := &CodeVariant{
		ID:              "test1",
		OriginalCode:    "x = 5\nprint(x)",
		TransformedCode: "x = 5\nprint(x)",
		TransformType:   "original",
	}

	ctx := context.Background()
	trace, err := predictor.PredictTrace(ctx, variant)
	if err != nil {
		t.Fatalf("PredictTrace failed: %v", err)
	}

	if trace.VariantID != "test1" {
		t.Error("Variant ID should match")
	}

	if len(trace.Steps) != 2 {
		t.Errorf("Expected 2 steps, got %d", len(trace.Steps))
	}

	if trace.Confidence != 0.85 {
		t.Errorf("Expected confidence 0.85, got %.2f", trace.Confidence)
	}
}

func TestAnalyzer(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.Timeout = 5 * time.Second

	mockResponse := `{
		"steps": [{"line": 1, "operation": "assign", "variables": {"x": 5}, "side_effects": []}],
		"final_state": {"variables": {"x": 5}, "outputs": [], "errors": []},
		"confidence": 0.9
	}`

	client := &MockLLMClient{Response: mockResponse}
	analyzer := NewAnalyzer(cfg, client)

	// Test ShouldAnalyze
	if !analyzer.ShouldAnalyze("Bash", "#!/bin/bash\necho hello world this is a test command") {
		t.Error("Should analyze Bash commands above min size")
	}

	if analyzer.ShouldAnalyze("Bash", "ls") {
		t.Error("Should not analyze small commands")
	}

	// Test basic analysis
	ctx := context.Background()
	code := `#!/bin/bash
x=5
y=10
result=$((x + y))
echo $result`

	result, err := analyzer.Analyze(ctx, code, "Bash")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result.Decision == "" {
		t.Error("Decision should be set")
	}

	if result.AggregateScore < 0 || result.AggregateScore > 1 {
		t.Errorf("Score should be between 0 and 1, got %.2f", result.AggregateScore)
	}
}

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple json",
			input:    `{"key": "value"}`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "json with text",
			input:    `Here is the result: {"key": "value"} and more text`,
			expected: `{"key": "value"}`,
		},
		{
			name:     "nested json",
			input:    `{"outer": {"inner": "value"}}`,
			expected: `{"outer": {"inner": "value"}}`,
		},
		{
			name:     "no json",
			input:    `Just some text`,
			expected: ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractJSON(tt.input)
			if result != tt.expected {
				t.Errorf("extractJSON(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
