package engine

import (
	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
)

// RuleEvaluation represents the result of evaluating a rule
type RuleEvaluation struct {
	Rule          *config.Rule
	Matched       bool
	MatchInfo     *MatchResult
	Decision      string
	Message       string
	ModifiedInput map[string]interface{} // Modified tool input when action=modify
}

// Evaluator evaluates rules against hook inputs
type Evaluator struct {
	matcher *Matcher
}

// NewEvaluator creates a new rule evaluator
func NewEvaluator() *Evaluator {
	return &Evaluator{
		matcher: NewMatcher(),
	}
}

// EvaluatePreToolUse evaluates rules against a PreToolUse input
func (e *Evaluator) EvaluatePreToolUse(rules []config.Rule, allowlist []config.Rule, input *hooks.PreToolUseInput) (*RuleEvaluation, error) {
	// Check allowlist first
	for i := range allowlist {
		rule := &allowlist[i]
		if !rule.Enabled {
			continue
		}

		matched, err := e.matchPreToolUseConditions(rule, input)
		if err != nil {
			logger.Warn().Err(err).Str("rule", rule.Name).Msg("Error evaluating allowlist rule")
			continue
		}

		if matched.Matched {
			logger.Debug().Str("rule", rule.Name).Msg("Allowlist rule matched, allowing")
			return &RuleEvaluation{
				Rule:     rule,
				Matched:  true,
				Decision: "allow",
				Message:  "Allowlisted: " + rule.Name,
			}, nil
		}
	}

	// Evaluate rules in priority order
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			logger.Debug().Str("rule", rule.Name).Msg("Rule disabled, skipping")
			continue
		}

		matched, err := e.matchPreToolUseConditions(rule, input)
		if err != nil {
			logger.Warn().Err(err).Str("rule", rule.Name).Msg("Error evaluating rule")
			continue
		}

		if matched.Matched {
			logger.Info().
				Str("rule", rule.Name).
				Str("pattern", matched.Pattern).
				Str("decision", rule.Decision).
				Msg("Rule matched")

			return &RuleEvaluation{
				Rule:      rule,
				Matched:   true,
				MatchInfo: matched,
				Decision:  rule.Decision,
				Message:   matched.Message,
			}, nil
		}
	}

	return &RuleEvaluation{Matched: false}, nil
}

// EvaluatePostToolUse evaluates rules against a PostToolUse input
func (e *Evaluator) EvaluatePostToolUse(rules []config.Rule, input *hooks.PostToolUseInput) (*RuleEvaluation, error) {
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			continue
		}

		matched, err := e.matchPostToolUseConditions(rule, input)
		if err != nil {
			logger.Warn().Err(err).Str("rule", rule.Name).Msg("Error evaluating rule")
			continue
		}

		if matched.Matched {
			logger.Info().
				Str("rule", rule.Name).
				Str("pattern", matched.Pattern).
				Str("decision", rule.Decision).
				Msg("Rule matched")

			return &RuleEvaluation{
				Rule:      rule,
				Matched:   true,
				MatchInfo: matched,
				Decision:  rule.Decision,
				Message:   matched.Message,
			}, nil
		}
	}

	return &RuleEvaluation{Matched: false}, nil
}

// EvaluateUserPrompt evaluates rules against a UserPromptSubmit input
func (e *Evaluator) EvaluateUserPrompt(rules []config.Rule, input *hooks.UserPromptSubmitInput) (*RuleEvaluation, error) {
	for i := range rules {
		rule := &rules[i]
		if !rule.Enabled {
			continue
		}

		if len(rule.Conditions.Prompt) == 0 {
			continue
		}

		matched, err := e.matcher.MatchPatterns(rule.Conditions.Prompt, input.Prompt)
		if err != nil {
			logger.Warn().Err(err).Str("rule", rule.Name).Msg("Error evaluating rule")
			continue
		}

		if matched.Matched {
			logger.Info().
				Str("rule", rule.Name).
				Str("pattern", matched.Pattern).
				Str("decision", rule.Decision).
				Msg("Rule matched")

			return &RuleEvaluation{
				Rule:      rule,
				Matched:   true,
				MatchInfo: matched,
				Decision:  rule.Decision,
				Message:   matched.Message,
			}, nil
		}
	}

	return &RuleEvaluation{Matched: false}, nil
}

func (e *Evaluator) matchPreToolUseConditions(rule *config.Rule, input *hooks.PreToolUseInput) (*MatchResult, error) {
	// Check tool name if specified
	if rule.Conditions.ToolName != "" {
		matched, err := e.matcher.MatchToolName(rule.Conditions.ToolName, input.ToolName)
		if err != nil {
			return nil, err
		}
		if !matched {
			return &MatchResult{Matched: false}, nil
		}
	}

	// Check tool input patterns
	if len(rule.Conditions.ToolInput) > 0 {
		return e.matcher.MatchToolInput(rule.Conditions.ToolInput, input.ToolInput)
	}

	// If we got here with a tool name match but no input patterns, it's a match
	if rule.Conditions.ToolName != "" {
		return &MatchResult{Matched: true, Message: "Tool name matched"}, nil
	}

	return &MatchResult{Matched: false}, nil
}

func (e *Evaluator) matchPostToolUseConditions(rule *config.Rule, input *hooks.PostToolUseInput) (*MatchResult, error) {
	// Check tool name if specified
	if rule.Conditions.ToolName != "" {
		matched, err := e.matcher.MatchToolName(rule.Conditions.ToolName, input.ToolName)
		if err != nil {
			return nil, err
		}
		if !matched {
			return &MatchResult{Matched: false}, nil
		}
	}

	// Check tool response patterns
	if len(rule.Conditions.ToolResponse) > 0 {
		return e.matcher.MatchToolResponse(rule.Conditions.ToolResponse, input.ToolResponse)
	}

	// Check tool input patterns
	if len(rule.Conditions.ToolInput) > 0 {
		return e.matcher.MatchToolInput(rule.Conditions.ToolInput, input.ToolInput)
	}

	return &MatchResult{Matched: false}, nil
}
