package trace

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/hooks"
	"github.com/ihavespoons/hooksy/internal/logger"
)

// Analyzer performs cross-event pattern detection
type Analyzer struct {
	store              SessionStore
	rules              []config.SequenceRule
	regexCache         sync.Map
	intentChecker      *IntentChecker
	transcriptAnalyzer *TranscriptAnalyzer
	transcriptCache    sync.Map // sessionID -> *TranscriptAnalysis
}

// NewAnalyzer creates a new pattern analyzer
func NewAnalyzer(store SessionStore, rules []config.SequenceRule) *Analyzer {
	return &Analyzer{
		store:              store,
		rules:              rules,
		intentChecker:      NewIntentChecker(store),
		transcriptAnalyzer: NewTranscriptAnalyzer(),
	}
}

// Analyze checks the current event against all sequence rules
// Returns nil if no patterns matched, or a HookOutput if a pattern triggered
func (a *Analyzer) Analyze(sessionID string, currentEvent *Event) *hooks.HookOutput {
	// Check for intent mismatches on PostToolUse events
	if currentEvent.EventType == hooks.PostToolUse && a.intentChecker != nil {
		if mismatch := a.intentChecker.CheckIntentMismatch(sessionID, currentEvent); mismatch != nil {
			logger.Info().
				Str("mismatch_type", mismatch.MismatchType).
				Str("severity", mismatch.Severity).
				Msg("Intent mismatch detected")

			// For critical mismatches, create a deny output
			if mismatch.Severity == "critical" {
				return hooks.NewDenyOutput(currentEvent.EventType,
					"Intent mismatch: "+mismatch.Description)
			}
		}
	}

	if len(a.rules) == 0 {
		return nil
	}

	for _, rule := range a.rules {
		if !rule.Enabled {
			continue
		}

		match := a.checkRule(sessionID, currentEvent, &rule)
		if match != nil {
			logger.Info().
				Str("rule", rule.Name).
				Str("decision", rule.Decision).
				Msg("Sequence pattern matched")

			return a.createOutput(match, currentEvent.EventType)
		}
	}

	return nil
}

// AnalyzeWithTranscript performs full analysis including transcript
func (a *Analyzer) AnalyzeWithTranscript(sessionID, transcriptPath string, currentEvent *Event) *hooks.HookOutput {
	// First do regular analysis
	output := a.Analyze(sessionID, currentEvent)

	// If transcript path provided, analyze it
	if transcriptPath != "" && a.transcriptAnalyzer != nil {
		transcriptOutput := a.checkTranscript(sessionID, transcriptPath, currentEvent.EventType)
		if transcriptOutput != nil {
			// Transcript analysis found something - combine with regular output
			if output == nil {
				return transcriptOutput
			}
			// Return most restrictive
			return a.mostRestrictive(output, transcriptOutput, currentEvent.EventType)
		}
	}

	return output
}

// checkTranscript analyzes the transcript for suspicious patterns
func (a *Analyzer) checkTranscript(sessionID, transcriptPath string, eventType hooks.EventType) *hooks.HookOutput {
	// Check cache first (avoid re-analyzing same transcript)
	cacheKey := sessionID + ":" + transcriptPath
	if cached, ok := a.transcriptCache.Load(cacheKey); ok {
		analysis := cached.(*TranscriptAnalysis)
		return a.transcriptAnalysisToOutput(analysis, eventType)
	}

	// Analyze transcript
	analysis, err := a.transcriptAnalyzer.AnalyzeTranscript(transcriptPath)
	if err != nil {
		logger.Debug().Err(err).Str("path", transcriptPath).Msg("Failed to analyze transcript")
		return nil
	}

	// Cache result
	a.transcriptCache.Store(cacheKey, analysis)

	logger.Debug().
		Float64("risk_score", analysis.RiskScore).
		Int("deception_indicators", len(analysis.DeceptionIndicators)).
		Int("monitoring_awareness", len(analysis.MonitoringAwareness)).
		Int("intent_mismatches", len(analysis.IntentActionMismatches)).
		Msg("Transcript analysis complete")

	return a.transcriptAnalysisToOutput(analysis, eventType)
}

// transcriptAnalysisToOutput converts transcript analysis to a HookOutput
func (a *Analyzer) transcriptAnalysisToOutput(analysis *TranscriptAnalysis, eventType hooks.EventType) *hooks.HookOutput {
	if analysis.RiskScore < 0.3 {
		return nil // Low risk, no action needed
	}

	// Build reason message
	var reasons []string
	if len(analysis.DeceptionIndicators) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d deception patterns", len(analysis.DeceptionIndicators)))
	}
	if len(analysis.IntentActionMismatches) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d intent mismatches", len(analysis.IntentActionMismatches)))
	}
	if len(analysis.MonitoringAwareness) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d monitoring awareness", len(analysis.MonitoringAwareness)))
	}
	if len(analysis.ObfuscationAttempts) > 0 {
		reasons = append(reasons, fmt.Sprintf("%d obfuscation attempts", len(analysis.ObfuscationAttempts)))
	}

	reason := fmt.Sprintf("Transcript analysis: risk=%.0f%%, %s",
		analysis.RiskScore*100,
		strings.Join(reasons, ", "))

	// High risk -> deny, medium risk -> ask
	if analysis.RiskScore >= 0.6 {
		logger.Warn().
			Float64("risk", analysis.RiskScore).
			Str("summary", analysis.Summary).
			Msg("High risk transcript detected")
		return hooks.NewDenyOutput(eventType, reason)
	}

	logger.Info().
		Float64("risk", analysis.RiskScore).
		Str("summary", analysis.Summary).
		Msg("Medium risk transcript detected")
	return hooks.NewAskOutput(eventType, reason)
}

// mostRestrictive returns the more restrictive of two outputs
func (a *Analyzer) mostRestrictive(a1, a2 *hooks.HookOutput, eventType hooks.EventType) *hooks.HookOutput {
	if a1 == nil {
		return a2
	}
	if a2 == nil {
		return a1
	}

	// block > deny > ask > allow
	priority := func(o *hooks.HookOutput) int {
		if !o.Continue {
			return 4 // block
		}
		if o.HookSpecificOutput != nil {
			switch o.HookSpecificOutput.PermissionDecision {
			case hooks.PermissionDeny:
				return 3
			case hooks.PermissionAsk:
				return 2
			}
		}
		return 1 // allow
	}

	if priority(a2) > priority(a1) {
		return a2
	}
	return a1
}

// GetTranscriptAnalysis returns cached or fresh transcript analysis
func (a *Analyzer) GetTranscriptAnalysis(transcriptPath string) (*TranscriptAnalysis, error) {
	return a.transcriptAnalyzer.AnalyzeTranscript(transcriptPath)
}

// checkRule checks if a single sequence rule matches
func (a *Analyzer) checkRule(sessionID string, currentEvent *Event, rule *config.SequenceRule) *PatternMatch {
	// Parse window duration
	window := 5 * time.Minute // default
	if rule.Window != "" {
		if d, err := time.ParseDuration(rule.Window); err == nil {
			window = d
		}
	}

	// Get recent events within the window
	since := time.Now().Add(-window)
	events, err := a.store.GetSessionEvents(sessionID, since)
	if err != nil {
		logger.Debug().Err(err).Msg("Failed to get session events for analysis")
		return nil
	}

	// Handle single-event count patterns (e.g., ">=3" occurrences)
	if len(rule.Events) == 1 && rule.Events[0].Count != "" {
		return a.checkCountPattern(events, currentEvent, rule)
	}

	// Handle multi-event sequence patterns
	return a.checkSequencePattern(events, currentEvent, rule)
}

// checkCountPattern checks for threshold-based patterns (e.g., ">=3" matching events)
func (a *Analyzer) checkCountPattern(events []*Event, currentEvent *Event, rule *config.SequenceRule) *PatternMatch {
	eventSpec := rule.Events[0]

	// Count matching events
	matchingEvents := make([]*Event, 0)

	// Include current event
	if a.eventMatches(currentEvent, &eventSpec) {
		matchingEvents = append(matchingEvents, currentEvent)
	}

	// Check historical events
	for _, event := range events {
		if a.eventMatches(event, &eventSpec) {
			matchingEvents = append(matchingEvents, event)
		}
	}

	// Parse count requirement (e.g., ">=3")
	required, op := parseCount(eventSpec.Count)

	count := len(matchingEvents)
	matched := false
	switch op {
	case ">=":
		matched = count >= required
	case ">":
		matched = count > required
	case "==", "=":
		matched = count == required
	case "<=":
		matched = count <= required
	case "<":
		matched = count < required
	}

	if matched {
		window, _ := time.ParseDuration(rule.Window)
		return &PatternMatch{
			RuleName:    rule.Name,
			Description: rule.Description,
			Severity:    rule.Severity,
			Decision:    rule.Decision,
			Message:     rule.Message,
			Events:      matchingEvents,
			Window:      window,
		}
	}

	return nil
}

// checkSequencePattern checks for ordered multi-event sequences
func (a *Analyzer) checkSequencePattern(events []*Event, currentEvent *Event, rule *config.SequenceRule) *PatternMatch {
	if len(rule.Events) == 0 {
		return nil
	}

	// Build a map of labeled events for "after" references
	labeledEvents := make(map[string]*Event)
	matchedSpecs := make([]bool, len(rule.Events))
	matchedEvents := make([]*Event, len(rule.Events))

	// Try to match each event spec against historical events
	for i, spec := range rule.Events {
		// If this spec has an "after" requirement, the referenced label must already be matched
		if spec.After != "" {
			if _, found := labeledEvents[spec.After]; !found {
				continue
			}
		}

		// Check historical events first
		for _, event := range events {
			if a.eventMatches(event, &spec) {
				// Check "after" constraint
				if spec.After != "" {
					refEvent := labeledEvents[spec.After]
					if refEvent == nil || event.Timestamp.Before(refEvent.Timestamp) {
						continue
					}
				}

				matchedSpecs[i] = true
				matchedEvents[i] = event
				if spec.Label != "" {
					labeledEvents[spec.Label] = event
				}
				break
			}
		}

		// If not matched yet, check current event
		if !matchedSpecs[i] && a.eventMatches(currentEvent, &spec) {
			// Check "after" constraint
			if spec.After != "" {
				refEvent := labeledEvents[spec.After]
				if refEvent == nil || currentEvent.Timestamp.Before(refEvent.Timestamp) {
					continue
				}
			}

			matchedSpecs[i] = true
			matchedEvents[i] = currentEvent
			if spec.Label != "" {
				labeledEvents[spec.Label] = currentEvent
			}
		}
	}

	// Check if all specs matched
	allMatched := true
	for _, matched := range matchedSpecs {
		if !matched {
			allMatched = false
			break
		}
	}

	if allMatched {
		window, _ := time.ParseDuration(rule.Window)

		// Collect only non-nil matched events
		finalEvents := make([]*Event, 0, len(matchedEvents))
		for _, e := range matchedEvents {
			if e != nil {
				finalEvents = append(finalEvents, e)
			}
		}

		return &PatternMatch{
			RuleName:    rule.Name,
			Description: rule.Description,
			Severity:    rule.Severity,
			Decision:    rule.Decision,
			Message:     rule.Message,
			Events:      finalEvents,
			Window:      window,
		}
	}

	return nil
}

// eventMatches checks if an event matches a sequence event specification
func (a *Analyzer) eventMatches(event *Event, spec *config.SequenceEvent) bool {
	// Check event type
	if spec.EventType != "" && event.EventType != spec.EventType {
		return false
	}

	// Check tool name (regex pattern)
	if spec.ToolName != "" {
		if !a.matchPattern(spec.ToolName, event.ToolName) {
			return false
		}
	}

	// Check tool input patterns
	if len(spec.ToolInput) > 0 {
		if event.ToolInput == nil {
			return false
		}
		for field, pattern := range spec.ToolInput {
			value, ok := event.ToolInput[field]
			if !ok {
				return false
			}
			strValue, ok := value.(string)
			if !ok {
				// Try to convert
				strValue = toString(value)
			}
			if !a.matchPattern(pattern, strValue) {
				return false
			}
		}
	}

	return true
}

// matchPattern checks if a value matches a regex pattern
func (a *Analyzer) matchPattern(pattern, value string) bool {
	// Get or compile regex
	cached, ok := a.regexCache.Load(pattern)
	if !ok {
		re, err := regexp.Compile(pattern)
		if err != nil {
			logger.Debug().
				Str("pattern", pattern).
				Err(err).
				Msg("Failed to compile pattern")
			return false
		}
		a.regexCache.Store(pattern, re)
		cached = re
	}

	re := cached.(*regexp.Regexp)
	return re.MatchString(value)
}

// createOutput creates a HookOutput for a matched pattern
func (a *Analyzer) createOutput(match *PatternMatch, eventType hooks.EventType) *hooks.HookOutput {
	reason := match.Message
	if reason == "" {
		reason = "Sequence pattern '" + match.RuleName + "' matched"
	}

	switch match.Decision {
	case "deny":
		return hooks.NewDenyOutput(eventType, reason)
	case "ask":
		return hooks.NewAskOutput(eventType, reason)
	case "block":
		return hooks.NewBlockOutput("Suspicious behavior detected", reason)
	default:
		return hooks.NewAllowOutput(eventType, reason)
	}
}

// parseCount parses a count expression like ">=3" into operator and value
func parseCount(expr string) (int, string) {
	expr = strings.TrimSpace(expr)

	operators := []string{">=", "<=", "==", ">", "<", "="}
	for _, op := range operators {
		if strings.HasPrefix(expr, op) {
			numStr := strings.TrimSpace(expr[len(op):])
			num, err := strconv.Atoi(numStr)
			if err != nil {
				return 1, ">="
			}
			return num, op
		}
	}

	// Default: just a number means >=
	num, err := strconv.Atoi(expr)
	if err != nil {
		return 1, ">="
	}
	return num, ">="
}

// toString converts a value to string representation
func toString(v interface{}) string {
	switch val := v.(type) {
	case string:
		return val
	case []byte:
		return string(val)
	default:
		return ""
	}
}
