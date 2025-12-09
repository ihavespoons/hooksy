package engine

import (
	"fmt"
	"regexp"
	"sync"

	"github.com/ihavespoons/hooksy/internal/config"
)

// Matcher handles regex pattern matching for rules
type Matcher struct {
	cache sync.Map // caches compiled regex patterns
}

// NewMatcher creates a new pattern matcher
func NewMatcher() *Matcher {
	return &Matcher{}
}

// MatchResult contains the result of a pattern match
type MatchResult struct {
	Matched bool
	Pattern string
	Message string
	Value   string
}

// MatchToolName checks if a tool name matches the pattern
func (m *Matcher) MatchToolName(pattern, toolName string) (bool, error) {
	if pattern == "" {
		return true, nil // Empty pattern matches everything
	}

	re, err := m.getOrCompile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid tool_name pattern %q: %w", pattern, err)
	}

	return re.MatchString(toolName), nil
}

// MatchPatterns checks a value against a list of patterns
func (m *Matcher) MatchPatterns(patterns []config.PatternMatch, value string) (*MatchResult, error) {
	for _, p := range patterns {
		re, err := m.getOrCompile(p.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p.Pattern, err)
		}

		if re.MatchString(value) {
			return &MatchResult{
				Matched: true,
				Pattern: p.Pattern,
				Message: p.Message,
				Value:   value,
			}, nil
		}
	}

	return &MatchResult{Matched: false}, nil
}

// MatchToolInput checks tool input fields against patterns
func (m *Matcher) MatchToolInput(patterns map[string][]config.PatternMatch, toolInput map[string]interface{}) (*MatchResult, error) {
	for field, fieldPatterns := range patterns {
		value, ok := toolInput[field]
		if !ok {
			continue
		}

		// Convert value to string for matching
		strValue := fmt.Sprintf("%v", value)

		result, err := m.MatchPatterns(fieldPatterns, strValue)
		if err != nil {
			return nil, err
		}

		if result.Matched {
			return result, nil
		}
	}

	return &MatchResult{Matched: false}, nil
}

// MatchToolResponse checks tool response against patterns
func (m *Matcher) MatchToolResponse(patterns []config.PatternMatch, toolResponse map[string]interface{}) (*MatchResult, error) {
	// Flatten the response to a string for pattern matching
	responseStr := flattenToString(toolResponse)

	return m.MatchPatterns(patterns, responseStr)
}

// getOrCompile retrieves a compiled regex from cache or compiles it
func (m *Matcher) getOrCompile(pattern string) (*regexp.Regexp, error) {
	if cached, ok := m.cache.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	m.cache.Store(pattern, re)
	return re, nil
}

// flattenToString converts a map to a string representation for pattern matching
func flattenToString(m map[string]interface{}) string {
	if m == nil {
		return ""
	}

	result := ""
	for key, value := range m {
		result += fmt.Sprintf("%s: %v\n", key, value)
	}
	return result
}
