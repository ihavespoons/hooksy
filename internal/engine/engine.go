package engine

import (
	"encoding/json"
	"fmt"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
)

// Engine is the main inspection engine
type Engine struct {
	cfg       *config.Config
	evaluator *Evaluator
}

// NewEngine creates a new inspection engine
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		cfg:       cfg,
		evaluator: NewEvaluator(),
	}
}

// Inspect inspects a hook input and returns the output
func (e *Engine) Inspect(eventType hooks.EventType, inputJSON []byte) (*hooks.HookOutput, error) {
	logger.Debug().
		Str("event", string(eventType)).
		Msg("Inspecting hook input")

	switch eventType {
	case hooks.PreToolUse:
		return e.inspectPreToolUse(inputJSON)
	case hooks.PostToolUse:
		return e.inspectPostToolUse(inputJSON)
	case hooks.UserPromptSubmit:
		return e.inspectUserPromptSubmit(inputJSON)
	case hooks.Stop, hooks.SubagentStop:
		return e.inspectStop(eventType, inputJSON)
	default:
		// For unsupported events, allow by default
		logger.Debug().
			Str("event", string(eventType)).
			Msg("Unsupported event type, allowing")
		return hooks.NewAllowOutput(eventType, "Event type not inspected"), nil
	}
}

func (e *Engine) inspectPreToolUse(inputJSON []byte) (*hooks.HookOutput, error) {
	var input hooks.PreToolUseInput
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("failed to parse PreToolUse input: %w", err)
	}

	logger.Debug().
		Str("tool", input.ToolName).
		Interface("input", input.ToolInput).
		Msg("Evaluating PreToolUse")

	rules := e.cfg.Rules.GetRulesForEvent(hooks.PreToolUse)
	evaluation, err := e.evaluator.EvaluatePreToolUse(rules, e.cfg.Allowlist, &input)
	if err != nil {
		return nil, err
	}

	// Apply modifications if the rule specifies action=modify
	if evaluation.Matched && evaluation.Rule != nil && evaluation.Rule.Action == "modify" {
		modifiedInput := e.applyModifications(input.ToolInput, evaluation.Rule.Modifications)
		evaluation.ModifiedInput = modifiedInput
	}

	return e.makeDecision(hooks.PreToolUse, evaluation)
}

func (e *Engine) inspectPostToolUse(inputJSON []byte) (*hooks.HookOutput, error) {
	var input hooks.PostToolUseInput
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("failed to parse PostToolUse input: %w", err)
	}

	logger.Debug().
		Str("tool", input.ToolName).
		Msg("Evaluating PostToolUse")

	rules := e.cfg.Rules.GetRulesForEvent(hooks.PostToolUse)
	evaluation, err := e.evaluator.EvaluatePostToolUse(rules, &input)
	if err != nil {
		return nil, err
	}

	return e.makeDecision(hooks.PostToolUse, evaluation)
}

func (e *Engine) inspectUserPromptSubmit(inputJSON []byte) (*hooks.HookOutput, error) {
	var input hooks.UserPromptSubmitInput
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("failed to parse UserPromptSubmit input: %w", err)
	}

	logger.Debug().
		Str("prompt", truncate(input.Prompt, 100)).
		Msg("Evaluating UserPromptSubmit")

	rules := e.cfg.Rules.GetRulesForEvent(hooks.UserPromptSubmit)
	evaluation, err := e.evaluator.EvaluateUserPrompt(rules, &input)
	if err != nil {
		return nil, err
	}

	return e.makeDecision(hooks.UserPromptSubmit, evaluation)
}

func (e *Engine) inspectStop(eventType hooks.EventType, inputJSON []byte) (*hooks.HookOutput, error) {
	var input hooks.StopInput
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("failed to parse Stop input: %w", err)
	}

	logger.Debug().
		Bool("stop_hook_active", input.StopHookActive).
		Msg("Evaluating Stop")

	// For now, just allow stop events
	// Future: LLM-based evaluation
	return hooks.NewAllowOutput(eventType, "Stop event allowed"), nil
}

func (e *Engine) makeDecision(eventType hooks.EventType, evaluation *RuleEvaluation) (*hooks.HookOutput, error) {
	// No rule matched, use default decision
	if !evaluation.Matched {
		defaultDecision := e.cfg.Settings.DefaultDecision
		logger.Debug().
			Str("default", defaultDecision).
			Msg("No rule matched, using default decision")

		switch defaultDecision {
		case "deny":
			return hooks.NewDenyOutput(eventType, "No matching rule, default deny"), nil
		case "ask":
			return hooks.NewAskOutput(eventType, "No matching rule, prompting user"), nil
		default:
			return hooks.NewAllowOutput(eventType, "All security checks passed"), nil
		}
	}

	// Apply matched rule's decision
	rule := evaluation.Rule
	reason := fmt.Sprintf("Rule '%s' triggered", rule.Name)
	if evaluation.Message != "" {
		reason += ": " + evaluation.Message
	}

	switch evaluation.Decision {
	case "deny":
		return hooks.NewDenyOutput(eventType, reason), nil
	case "ask":
		return hooks.NewAskOutput(eventType, reason), nil
	case "block":
		systemMsg := rule.SystemMessage
		if systemMsg == "" {
			systemMsg = reason
		}
		return hooks.NewBlockOutput("Security violation detected", systemMsg), nil
	case "allow":
		// Check if there are modifications to apply
		if rule.Action == "modify" && evaluation.ModifiedInput != nil {
			logger.Info().
				Str("rule", rule.Name).
				Interface("modified_input", evaluation.ModifiedInput).
				Msg("Applying input modifications")
			return hooks.NewModifyOutput(eventType, reason+" (input modified)", evaluation.ModifiedInput), nil
		}
		return hooks.NewAllowOutput(eventType, reason), nil
	default:
		return hooks.NewAllowOutput(eventType, reason), nil
	}
}

// applyModifications applies the modification rules to the tool input
func (e *Engine) applyModifications(toolInput map[string]interface{}, mods *config.Modifications) map[string]interface{} {
	if mods == nil || mods.ToolInput == nil {
		return toolInput
	}

	// Create a copy of the input to avoid modifying the original
	result := make(map[string]interface{})
	for k, v := range toolInput {
		result[k] = v
	}

	// Apply modifications for each field
	for field, action := range mods.ToolInput {
		currentValue, exists := result[field]
		if !exists {
			continue
		}

		// Convert current value to string for modification
		strValue, ok := currentValue.(string)
		if !ok {
			// Try to convert non-string values
			strValue = fmt.Sprintf("%v", currentValue)
		}

		// Apply the modification action
		if action.Replace != "" {
			result[field] = action.Replace
			logger.Debug().
				Str("field", field).
				Str("old", strValue).
				Str("new", action.Replace).
				Msg("Replaced field value")
		} else {
			newValue := strValue
			if action.Prepend != "" {
				newValue = action.Prepend + newValue
			}
			if action.Append != "" {
				newValue = newValue + action.Append
			}
			result[field] = newValue
			logger.Debug().
				Str("field", field).
				Str("old", strValue).
				Str("new", newValue).
				Msg("Modified field value")
		}
	}

	return result
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
