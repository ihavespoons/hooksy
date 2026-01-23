package llm

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
)

// Analyzer coordinates LLM-based analysis of hook events.
type Analyzer struct {
	manager  *Manager
	cfg      *Config
	triggers map[hooks.EventType][]AnalysisTrigger

	// compiledPatterns caches compiled regex patterns
	compiledPatterns sync.Map
}

// NewAnalyzer creates a new analyzer with the given manager and config.
func NewAnalyzer(manager *Manager, cfg *Config) *Analyzer {
	a := &Analyzer{
		manager:  manager,
		cfg:      cfg,
		triggers: make(map[hooks.EventType][]AnalysisTrigger),
	}

	// Index triggers by event type
	for _, trigger := range cfg.Analysis.Triggers {
		eventType := hooks.EventType(trigger.EventType)
		a.triggers[eventType] = append(a.triggers[eventType], trigger)
	}

	return a
}

// ShouldAnalyze checks if an event should trigger LLM analysis.
func (a *Analyzer) ShouldAnalyze(eventType hooks.EventType, toolName string, ruleMatched bool, ruleDecision string) (bool, []AnalysisType, Mode) {
	if !a.cfg.Enabled {
		return false, nil, ""
	}

	triggers, ok := a.triggers[eventType]
	if !ok {
		return false, nil, ""
	}

	var analysisTypes []AnalysisType
	var mode Mode = a.cfg.Mode

	for _, trigger := range triggers {
		if a.matchesTrigger(trigger, toolName, ruleMatched, ruleDecision) {
			analysisTypes = append(analysisTypes, trigger.AnalysisTypes...)
			if trigger.Mode != "" {
				mode = trigger.Mode
			}
		}
	}

	if len(analysisTypes) == 0 {
		return false, nil, ""
	}

	// Deduplicate analysis types
	analysisTypes = deduplicateAnalysisTypes(analysisTypes)

	return true, analysisTypes, mode
}

// matchesTrigger checks if conditions match for a trigger.
func (a *Analyzer) matchesTrigger(trigger AnalysisTrigger, toolName string, ruleMatched bool, ruleDecision string) bool {
	cond := trigger.Conditions

	// Always trigger
	if cond.Always {
		return true
	}

	// Check tool name patterns
	if len(cond.ToolNames) > 0 {
		matched := false
		for _, pattern := range cond.ToolNames {
			if a.matchPattern(pattern, toolName) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check no rule match condition
	if cond.NoRuleMatch && ruleMatched {
		return false
	}

	// Check rule decision condition
	if len(cond.RuleDecision) > 0 {
		matched := false
		for _, decision := range cond.RuleDecision {
			if decision == ruleDecision {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// matchPattern matches a regex pattern against a value with caching.
func (a *Analyzer) matchPattern(pattern, value string) bool {
	// Check cache
	if cached, ok := a.compiledPatterns.Load(pattern); ok {
		return cached.(*regexp.Regexp).MatchString(value)
	}

	// Compile and cache
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	a.compiledPatterns.Store(pattern, re)
	return re.MatchString(value)
}

// AnalyzePreToolUse performs analysis for a PreToolUse event.
func (a *Analyzer) AnalyzePreToolUse(ctx context.Context, input *hooks.PreToolUseInput, ruleDecision, ruleReason string) (*AnalysisResponse, error) {
	should, analysisTypes, mode := a.ShouldAnalyze(
		hooks.PreToolUse,
		input.ToolName,
		ruleDecision != "",
		ruleDecision,
	)
	if !should {
		return nil, nil
	}

	// For PreToolUse, contextual analysis is most relevant
	var primaryType AnalysisType = AnalysisContextual
	for _, t := range analysisTypes {
		if t == AnalysisContextual {
			primaryType = t
			break
		}
	}

	req := &AnalysisRequest{
		Type:           primaryType,
		EventType:      hooks.PreToolUse,
		SessionID:      input.SessionID,
		TranscriptPath: input.TranscriptPath,
		ToolName:       input.ToolName,
		ToolInput:      input.ToolInput,
		ToolUseID:      input.ToolUseID,
		RuleDecision:   ruleDecision,
		RuleReason:     ruleReason,
		Context: &AnalysisContext{
			Cwd: input.Cwd,
		},
		CustomPrompt: a.cfg.Prompts.Contextual,
		SystemPrompt: a.cfg.Prompts.SystemPrompt,
	}

	return a.performAnalysis(ctx, req, mode)
}

// AnalyzePostToolUse performs analysis for a PostToolUse event.
func (a *Analyzer) AnalyzePostToolUse(ctx context.Context, input *hooks.PostToolUseInput, ruleDecision, ruleReason string) (*AnalysisResponse, error) {
	should, analysisTypes, mode := a.ShouldAnalyze(
		hooks.PostToolUse,
		input.ToolName,
		ruleDecision != "",
		ruleDecision,
	)
	if !should {
		return nil, nil
	}

	// For PostToolUse, intent vs action analysis is most relevant
	var primaryType AnalysisType = AnalysisIntentAction
	for _, t := range analysisTypes {
		if t == AnalysisIntentAction {
			primaryType = t
			break
		}
	}

	req := &AnalysisRequest{
		Type:           primaryType,
		EventType:      hooks.PostToolUse,
		SessionID:      input.SessionID,
		TranscriptPath: input.TranscriptPath,
		ToolName:       input.ToolName,
		ToolInput:      input.ToolInput,
		ToolResponse:   input.ToolResponse,
		ToolUseID:      input.ToolUseID,
		RuleDecision:   ruleDecision,
		RuleReason:     ruleReason,
		Context: &AnalysisContext{
			Cwd: input.Cwd,
		},
		CustomPrompt: a.cfg.Prompts.IntentAction,
		SystemPrompt: a.cfg.Prompts.SystemPrompt,
	}

	return a.performAnalysis(ctx, req, mode)
}

// AnalyzeStop performs analysis for a Stop event.
func (a *Analyzer) AnalyzeStop(ctx context.Context, input *hooks.StopInput, ruleDecision, ruleReason string) (*AnalysisResponse, error) {
	should, analysisTypes, mode := a.ShouldAnalyze(
		hooks.Stop,
		"",
		ruleDecision != "",
		ruleDecision,
	)
	if !should {
		return nil, nil
	}

	// For Stop, stop analysis is most relevant
	var primaryType AnalysisType = AnalysisStop
	for _, t := range analysisTypes {
		if t == AnalysisStop {
			primaryType = t
			break
		}
	}

	// Use stop prompt or transcript prompt based on analysis type
	customPrompt := a.cfg.Prompts.Stop
	if primaryType == AnalysisTranscript && a.cfg.Prompts.Transcript != "" {
		customPrompt = a.cfg.Prompts.Transcript
	}

	req := &AnalysisRequest{
		Type:           primaryType,
		EventType:      hooks.Stop,
		SessionID:      input.SessionID,
		TranscriptPath: input.TranscriptPath,
		RuleDecision:   ruleDecision,
		RuleReason:     ruleReason,
		Context: &AnalysisContext{
			Cwd: input.Cwd,
		},
		CustomPrompt: customPrompt,
		SystemPrompt: a.cfg.Prompts.SystemPrompt,
	}

	return a.performAnalysis(ctx, req, mode)
}

// AnalyzeUserPrompt performs analysis for a UserPromptSubmit event.
func (a *Analyzer) AnalyzeUserPrompt(ctx context.Context, input *hooks.UserPromptSubmitInput, ruleDecision, ruleReason string) (*AnalysisResponse, error) {
	should, analysisTypes, mode := a.ShouldAnalyze(
		hooks.UserPromptSubmit,
		"",
		ruleDecision != "",
		ruleDecision,
	)
	if !should {
		return nil, nil
	}

	var primaryType AnalysisType = AnalysisContextual
	if len(analysisTypes) > 0 {
		primaryType = analysisTypes[0]
	}

	req := &AnalysisRequest{
		Type:           primaryType,
		EventType:      hooks.UserPromptSubmit,
		SessionID:      input.SessionID,
		TranscriptPath: input.TranscriptPath,
		Prompt:         input.Prompt,
		RuleDecision:   ruleDecision,
		RuleReason:     ruleReason,
		Context: &AnalysisContext{
			Cwd: input.Cwd,
		},
		CustomPrompt: a.cfg.Prompts.UserPrompt,
		SystemPrompt: a.cfg.Prompts.SystemPrompt,
	}

	return a.performAnalysis(ctx, req, mode)
}

// performAnalysis executes the analysis with the given mode.
func (a *Analyzer) performAnalysis(ctx context.Context, req *AnalysisRequest, mode Mode) (*AnalysisResponse, error) {
	switch mode {
	case ModeAsync:
		// Fire and forget, log results
		go func() {
			asyncCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			resp, err := a.manager.Analyze(asyncCtx, req)
			if err != nil {
				logger.Warn().
					Str("event_type", string(req.EventType)).
					Err(err).
					Msg("Async LLM analysis failed")
				return
			}

			logger.Info().
				Str("event_type", string(req.EventType)).
				Str("decision", string(resp.Decision)).
				Float32("confidence", resp.Confidence).
				Str("provider", string(resp.ProviderType)).
				Msg("Async LLM analysis complete")
		}()
		return nil, nil

	case ModeSync, ModeHybrid:
		// For hybrid mode during pre-events, use sync
		return a.manager.Analyze(ctx, req)

	default:
		return a.manager.Analyze(ctx, req)
	}
}

// CrossValidate combines rule-based and LLM decisions using most-restrictive-wins.
func (a *Analyzer) CrossValidate(ruleDecision string, llmResponse *AnalysisResponse) string {
	if llmResponse == nil {
		return ruleDecision
	}

	// Check confidence threshold
	if llmResponse.Confidence < a.cfg.Analysis.MinConfidence {
		logger.Debug().
			Float32("confidence", llmResponse.Confidence).
			Float32("min_confidence", a.cfg.Analysis.MinConfidence).
			Msg("LLM confidence below threshold, using rule decision")
		return ruleDecision
	}

	// Priority: block > deny > ask > allow
	priority := map[string]int{
		"allow": 0,
		"ask":   1,
		"deny":  2,
		"block": 3,
	}

	rulePriority := priority[ruleDecision]
	llmPriority := priority[string(llmResponse.Decision)]

	// Most restrictive wins
	if llmPriority > rulePriority {
		logger.Info().
			Str("rule_decision", ruleDecision).
			Str("llm_decision", string(llmResponse.Decision)).
			Str("reasoning", llmResponse.Reasoning).
			Msg("LLM decision more restrictive, overriding rule")
		return string(llmResponse.Decision)
	}

	return ruleDecision
}

// deduplicateAnalysisTypes removes duplicates from a slice of AnalysisType.
func deduplicateAnalysisTypes(types []AnalysisType) []AnalysisType {
	seen := make(map[AnalysisType]bool)
	result := make([]AnalysisType, 0, len(types))
	for _, t := range types {
		if !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return result
}
