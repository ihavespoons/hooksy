package engine

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/ihavespoons/hooksy/internal/trace"
)

// Engine is the main inspection engine
type Engine struct {
	cfg       *config.Config
	evaluator *Evaluator
	store     trace.SessionStore
	analyzer  *trace.Analyzer
}

// NewEngine creates a new inspection engine
func NewEngine(cfg *config.Config) *Engine {
	return &Engine{
		cfg:       cfg,
		evaluator: NewEvaluator(),
	}
}

// NewEngineWithTracing creates a new inspection engine with tracing enabled
func NewEngineWithTracing(cfg *config.Config, store trace.SessionStore) *Engine {
	e := &Engine{
		cfg:       cfg,
		evaluator: NewEvaluator(),
		store:     store,
	}
	if store != nil && len(cfg.SequenceRules) > 0 {
		e.analyzer = trace.NewAnalyzer(store, cfg.SequenceRules)
	}
	return e
}

// SetStore sets the session store for tracing (can be used to enable tracing after engine creation)
func (e *Engine) SetStore(store trace.SessionStore) {
	e.store = store
	if store != nil && len(e.cfg.SequenceRules) > 0 {
		e.analyzer = trace.NewAnalyzer(store, e.cfg.SequenceRules)
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
	case hooks.SessionStart:
		return e.inspectSessionStart(inputJSON)
	case hooks.SessionEnd:
		return e.inspectSessionEnd(inputJSON)
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

	// Ensure session exists for tracing
	if e.store != nil {
		_, err := e.store.GetOrCreateSession(input.SessionID, input.Cwd, input.TranscriptPath)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to get/create session for tracing")
		}
	}

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

	// Make initial decision from rule evaluation
	output, err := e.makeDecision(hooks.PreToolUse, evaluation)
	if err != nil {
		return nil, err
	}

	// Store event for tracing
	decision := e.extractDecision(output)
	ruleMatched := ""
	if evaluation.Rule != nil {
		ruleMatched = evaluation.Rule.Name
	}

	event := &trace.Event{
		SessionID: input.SessionID,
		ToolUseID: input.ToolUseID,
		EventType: hooks.PreToolUse,
		ToolName:  input.ToolName,
		ToolInput: input.ToolInput,
		Timestamp: time.Now(),
		Decision:  decision,
		RuleMatched: ruleMatched,
	}

	if e.store != nil {
		if err := e.store.StoreEvent(event); err != nil {
			logger.Debug().Err(err).Msg("Failed to store event for tracing")
		}
	}

	// Run sequence and transcript analysis if analyzer is configured
	if e.analyzer != nil {
		sequenceOutput := e.analyzer.AnalyzeWithTranscript(input.SessionID, input.TranscriptPath, event)
		output = e.combineOutputs(output, sequenceOutput, hooks.PreToolUse)
	}

	return output, nil
}

func (e *Engine) inspectPostToolUse(inputJSON []byte) (*hooks.HookOutput, error) {
	var input hooks.PostToolUseInput
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("failed to parse PostToolUse input: %w", err)
	}

	logger.Debug().
		Str("tool", input.ToolName).
		Msg("Evaluating PostToolUse")

	// Ensure session exists for tracing
	if e.store != nil {
		_, err := e.store.GetOrCreateSession(input.SessionID, input.Cwd, input.TranscriptPath)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to get/create session for tracing")
		}
	}

	rules := e.cfg.Rules.GetRulesForEvent(hooks.PostToolUse)
	evaluation, err := e.evaluator.EvaluatePostToolUse(rules, &input)
	if err != nil {
		return nil, err
	}

	// Make initial decision from rule evaluation
	output, err := e.makeDecision(hooks.PostToolUse, evaluation)
	if err != nil {
		return nil, err
	}

	// Store event for tracing
	decision := e.extractDecision(output)
	ruleMatched := ""
	if evaluation.Rule != nil {
		ruleMatched = evaluation.Rule.Name
	}

	event := &trace.Event{
		SessionID:    input.SessionID,
		ToolUseID:    input.ToolUseID,
		EventType:    hooks.PostToolUse,
		ToolName:     input.ToolName,
		ToolInput:    input.ToolInput,
		ToolResponse: input.ToolResponse,
		Timestamp:    time.Now(),
		Decision:     decision,
		RuleMatched:  ruleMatched,
	}

	if e.store != nil {
		if err := e.store.StoreEvent(event); err != nil {
			logger.Debug().Err(err).Msg("Failed to store event for tracing")
		}
	}

	// Run sequence and transcript analysis if analyzer is configured
	if e.analyzer != nil {
		sequenceOutput := e.analyzer.AnalyzeWithTranscript(input.SessionID, input.TranscriptPath, event)
		output = e.combineOutputs(output, sequenceOutput, hooks.PostToolUse)
	}

	return output, nil
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

func (e *Engine) inspectSessionStart(inputJSON []byte) (*hooks.HookOutput, error) {
	var input hooks.SessionStartInput
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("failed to parse SessionStart input: %w", err)
	}

	logger.Debug().
		Str("session_id", input.SessionID).
		Str("source", input.Source).
		Msg("Session starting")

	// Initialize session for tracing
	if e.store != nil {
		_, err := e.store.GetOrCreateSession(input.SessionID, input.Cwd, input.TranscriptPath)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to create session for tracing")
		}

		// Probabilistically run cleanup
		trace.MaybeRunCleanup(e.store, e.cfg.Settings.Trace)
	}

	return hooks.NewAllowOutput(hooks.SessionStart, "Session started"), nil
}

func (e *Engine) inspectSessionEnd(inputJSON []byte) (*hooks.HookOutput, error) {
	var input hooks.SessionEndInput
	if err := json.Unmarshal(inputJSON, &input); err != nil {
		return nil, fmt.Errorf("failed to parse SessionEnd input: %w", err)
	}

	logger.Debug().
		Str("session_id", input.SessionID).
		Str("reason", input.Reason).
		Msg("Session ending")

	// Clean up excess events for this session
	if e.store != nil {
		maxEvents := e.cfg.Settings.Trace.MaxEventsPerSession
		if maxEvents <= 0 {
			maxEvents = 1000
		}
		_, err := e.store.CleanupExcessEvents(input.SessionID, maxEvents)
		if err != nil {
			logger.Debug().Err(err).Msg("Failed to cleanup excess events")
		}
	}

	return hooks.NewAllowOutput(hooks.SessionEnd, "Session ended"), nil
}

// extractDecision extracts the decision string from a HookOutput
func (e *Engine) extractDecision(output *hooks.HookOutput) string {
	if output == nil {
		return "allow"
	}
	if !output.Continue {
		return "block"
	}
	if output.HookSpecificOutput != nil {
		return string(output.HookSpecificOutput.PermissionDecision)
	}
	return "allow"
}

// combineOutputs combines the rule-based output with sequence analysis output
// Most restrictive decision wins: block > deny > ask > allow
func (e *Engine) combineOutputs(ruleOutput, sequenceOutput *hooks.HookOutput, eventType hooks.EventType) *hooks.HookOutput {
	if sequenceOutput == nil {
		return ruleOutput
	}

	ruleDecision := e.extractDecision(ruleOutput)
	sequenceDecision := e.extractDecision(sequenceOutput)

	// Decision priority order (most restrictive first)
	priority := map[string]int{
		"block": 4,
		"deny":  3,
		"ask":   2,
		"allow": 1,
	}

	rulePriority := priority[ruleDecision]
	sequencePriority := priority[sequenceDecision]

	// If sequence analysis has a more restrictive decision, use it
	if sequencePriority > rulePriority {
		logger.Info().
			Str("rule_decision", ruleDecision).
			Str("sequence_decision", sequenceDecision).
			Msg("Sequence analysis triggered more restrictive decision")
		return sequenceOutput
	}

	return ruleOutput
}
