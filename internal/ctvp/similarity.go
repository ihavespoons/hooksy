package ctvp

import (
	"fmt"
	"math"
	"reflect"
	"strings"
)

// SimilarityCalculator computes similarity between execution traces
type SimilarityCalculator struct {
	config *SimilarityConfig
}

// NewSimilarityCalculator creates a new similarity calculator
func NewSimilarityCalculator(config *SimilarityConfig) *SimilarityCalculator {
	return &SimilarityCalculator{
		config: config,
	}
}

// ComputeSimilarity calculates the similarity between two execution traces
func (s *SimilarityCalculator) ComputeSimilarity(trace1, trace2 *ExecutionTrace) *SimilarityResult {
	result := &SimilarityResult{
		Anomalies: make([]TraceAnomaly, 0),
	}

	// Handle error cases
	if trace1.Error != "" || trace2.Error != "" {
		result.Score = 0
		if trace1.Error != "" && trace2.Error != "" {
			// Both errored - could be similar behavior
			result.Score = 0.5
		}
		result.Anomalies = append(result.Anomalies, TraceAnomaly{
			VariantA:    trace1.VariantID,
			VariantB:    trace2.VariantID,
			AnomalyType: "trace_error",
			Description: fmt.Sprintf("Trace errors: [%s] vs [%s]", trace1.Error, trace2.Error),
			Severity:    0.8,
		})
		return result
	}

	// Calculate component scores
	result.StepAlignment = s.computeStepAlignment(trace1, trace2, result)
	result.StateMatch = s.computeStateMatch(trace1, trace2, result)
	result.OutputMatch = s.computeOutputMatch(trace1, trace2, result)

	// Weighted combination
	result.Score = s.config.StepAlignmentWeight*result.StepAlignment +
		s.config.StateMatchWeight*result.StateMatch +
		s.config.OutputMatchWeight*result.OutputMatch

	return result
}

// computeStepAlignment compares execution step sequences
func (s *SimilarityCalculator) computeStepAlignment(trace1, trace2 *ExecutionTrace, result *SimilarityResult) float64 {
	if len(trace1.Steps) == 0 && len(trace2.Steps) == 0 {
		return 1.0 // Both empty = identical
	}
	if len(trace1.Steps) == 0 || len(trace2.Steps) == 0 {
		result.Anomalies = append(result.Anomalies, TraceAnomaly{
			VariantA:    trace1.VariantID,
			VariantB:    trace2.VariantID,
			AnomalyType: "step_count_mismatch",
			Description: fmt.Sprintf("Step counts: %d vs %d", len(trace1.Steps), len(trace2.Steps)),
			Severity:    0.7,
		})
		return 0.0
	}

	// Use edit distance for step alignment
	if s.config.IgnoreOrdering {
		return s.computeSetSimilarity(trace1.Steps, trace2.Steps, result)
	}
	return s.computeSequenceSimilarity(trace1.Steps, trace2.Steps, result)
}

// computeSequenceSimilarity uses Levenshtein-like distance for step sequences
func (s *SimilarityCalculator) computeSequenceSimilarity(steps1, steps2 []TraceStep, result *SimilarityResult) float64 {
	m, n := len(steps1), len(steps2)
	if m == 0 && n == 0 {
		return 1.0
	}

	// Create DP table for edit distance
	dp := make([][]float64, m+1)
	for i := range dp {
		dp[i] = make([]float64, n+1)
	}

	// Initialize
	for i := 0; i <= m; i++ {
		dp[i][0] = float64(i)
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = float64(j)
	}

	// Fill DP table
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			cost := s.stepDistance(steps1[i-1], steps2[j-1], result)
			dp[i][j] = min3(
				dp[i-1][j]+1,      // deletion
				dp[i][j-1]+1,      // insertion
				dp[i-1][j-1]+cost, // substitution
			)
		}
	}

	// Normalize to 0-1 similarity
	maxLen := float64(max(m, n))
	distance := dp[m][n]
	return 1.0 - (distance / maxLen)
}

// stepDistance computes distance between two steps (0 = identical, 1 = completely different)
func (s *SimilarityCalculator) stepDistance(step1, step2 TraceStep, result *SimilarityResult) float64 {
	var distance float64

	// Compare operations
	if !s.operationsMatch(step1.Operation, step2.Operation) {
		distance += 0.5
	}

	// Compare side effects (critical for security)
	sideEffectSim := s.compareSideEffects(step1.SideEffects, step2.SideEffects)
	if sideEffectSim < 0.5 {
		result.Anomalies = append(result.Anomalies, TraceAnomaly{
			AnomalyType: "side_effect_divergence",
			Description: fmt.Sprintf("Side effects differ: %v vs %v", step1.SideEffects, step2.SideEffects),
			Severity:    0.9,
			Evidence: map[string]interface{}{
				"step1_effects": step1.SideEffects,
				"step2_effects": step2.SideEffects,
			},
		})
	}
	distance += (1.0 - sideEffectSim) * 0.5

	return minFloat(distance, 1.0)
}

// operationsMatch checks if two operations are semantically equivalent
func (s *SimilarityCalculator) operationsMatch(op1, op2 string) bool {
	// Normalize operations
	op1 = strings.ToLower(strings.TrimSpace(op1))
	op2 = strings.ToLower(strings.TrimSpace(op2))

	if op1 == op2 {
		return true
	}

	// Check for equivalent operations
	equivalents := map[string][]string{
		"assignment":    {"assign", "set", "store"},
		"function_call": {"call", "invoke", "execute"},
		"return":        {"return", "exit"},
		"loop":          {"for", "while", "iterate"},
		"conditional":   {"if", "branch", "switch"},
	}

	for _, group := range equivalents {
		has1, has2 := false, false
		for _, equiv := range group {
			if strings.Contains(op1, equiv) {
				has1 = true
			}
			if strings.Contains(op2, equiv) {
				has2 = true
			}
		}
		if has1 && has2 {
			return true
		}
	}

	return false
}

// compareSideEffects computes similarity between side effect lists
func (s *SimilarityCalculator) compareSideEffects(effects1, effects2 []string) float64 {
	if len(effects1) == 0 && len(effects2) == 0 {
		return 1.0
	}
	if len(effects1) == 0 || len(effects2) == 0 {
		return 0.0
	}

	// Normalize and compare
	norm1 := make(map[string]bool)
	norm2 := make(map[string]bool)

	for _, e := range effects1 {
		norm1[s.normalizeSideEffect(e)] = true
	}
	for _, e := range effects2 {
		norm2[s.normalizeSideEffect(e)] = true
	}

	// Jaccard similarity
	intersection := 0
	for k := range norm1 {
		if norm2[k] {
			intersection++
		}
	}

	union := len(norm1) + len(norm2) - intersection
	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

// normalizeSideEffect normalizes a side effect description
func (s *SimilarityCalculator) normalizeSideEffect(effect string) string {
	effect = strings.ToLower(effect)

	// Extract operation type
	opTypes := []string{"file write", "file read", "network", "process", "env"}
	for _, op := range opTypes {
		if strings.Contains(effect, op) {
			return op
		}
	}

	return effect
}

// computeSetSimilarity compares steps as unordered sets
func (s *SimilarityCalculator) computeSetSimilarity(steps1, steps2 []TraceStep, result *SimilarityResult) float64 {
	if len(steps1) == 0 && len(steps2) == 0 {
		return 1.0
	}

	// Create operation fingerprints
	ops1 := make(map[string]int)
	ops2 := make(map[string]int)

	for _, step := range steps1 {
		ops1[s.stepFingerprint(step)]++
	}
	for _, step := range steps2 {
		ops2[s.stepFingerprint(step)]++
	}

	// Compare multisets
	allOps := make(map[string]bool)
	for op := range ops1 {
		allOps[op] = true
	}
	for op := range ops2 {
		allOps[op] = true
	}

	matched := 0
	total := 0
	for op := range allOps {
		c1 := ops1[op]
		c2 := ops2[op]
		matched += minInt(c1, c2)
		total += maxInt(c1, c2)
	}

	if total == 0 {
		return 1.0
	}

	return float64(matched) / float64(total)
}

// stepFingerprint creates a comparable fingerprint for a step
func (s *SimilarityCalculator) stepFingerprint(step TraceStep) string {
	// Combine operation and side effects into a fingerprint
	effects := strings.Join(step.SideEffects, "|")
	return fmt.Sprintf("%s:%s", step.Operation, effects)
}

// computeStateMatch compares final states
func (s *SimilarityCalculator) computeStateMatch(trace1, trace2 *ExecutionTrace, result *SimilarityResult) float64 {
	var totalScore float64
	var components int

	// Compare variables
	if len(trace1.FinalState.Variables) > 0 || len(trace2.FinalState.Variables) > 0 {
		varScore := s.compareVariables(trace1.FinalState.Variables, trace2.FinalState.Variables)
		totalScore += varScore
		components++

		if varScore < 0.5 {
			result.Anomalies = append(result.Anomalies, TraceAnomaly{
				VariantA:    trace1.VariantID,
				VariantB:    trace2.VariantID,
				AnomalyType: "variable_state_divergence",
				Description: "Final variable states significantly differ",
				Severity:    0.6,
				Evidence: map[string]interface{}{
					"vars1": trace1.FinalState.Variables,
					"vars2": trace2.FinalState.Variables,
				},
			})
		}
	}

	// Compare errors
	if len(trace1.FinalState.Errors) > 0 || len(trace2.FinalState.Errors) > 0 {
		errScore := s.compareStringLists(trace1.FinalState.Errors, trace2.FinalState.Errors)
		totalScore += errScore
		components++

		if errScore < 0.5 {
			result.Anomalies = append(result.Anomalies, TraceAnomaly{
				VariantA:    trace1.VariantID,
				VariantB:    trace2.VariantID,
				AnomalyType: "error_divergence",
				Description: "Error states significantly differ",
				Severity:    0.8,
				Evidence: map[string]interface{}{
					"errors1": trace1.FinalState.Errors,
					"errors2": trace2.FinalState.Errors,
				},
			})
		}
	}

	if components == 0 {
		return 1.0
	}

	return totalScore / float64(components)
}

// compareVariables compares two variable maps
func (s *SimilarityCalculator) compareVariables(vars1, vars2 map[string]interface{}) float64 {
	if len(vars1) == 0 && len(vars2) == 0 {
		return 1.0
	}

	// Collect all keys
	allKeys := make(map[string]bool)
	for k := range vars1 {
		allKeys[k] = true
	}
	for k := range vars2 {
		allKeys[k] = true
	}

	matched := 0
	for k := range allKeys {
		v1, ok1 := vars1[k]
		v2, ok2 := vars2[k]

		if ok1 && ok2 && reflect.DeepEqual(v1, v2) {
			matched++
		}
	}

	return float64(matched) / float64(len(allKeys))
}

// computeOutputMatch compares outputs
func (s *SimilarityCalculator) computeOutputMatch(trace1, trace2 *ExecutionTrace, result *SimilarityResult) float64 {
	score := s.compareStringLists(trace1.FinalState.Outputs, trace2.FinalState.Outputs)

	if score < 0.5 && (len(trace1.FinalState.Outputs) > 0 || len(trace2.FinalState.Outputs) > 0) {
		result.Anomalies = append(result.Anomalies, TraceAnomaly{
			VariantA:    trace1.VariantID,
			VariantB:    trace2.VariantID,
			AnomalyType: "output_divergence",
			Description: "Outputs significantly differ",
			Severity:    0.7,
			Evidence: map[string]interface{}{
				"outputs1": trace1.FinalState.Outputs,
				"outputs2": trace2.FinalState.Outputs,
			},
		})
	}

	return score
}

// compareStringLists computes similarity between string lists
func (s *SimilarityCalculator) compareStringLists(list1, list2 []string) float64 {
	if len(list1) == 0 && len(list2) == 0 {
		return 1.0
	}
	if len(list1) == 0 || len(list2) == 0 {
		return 0.0
	}

	// Convert to sets
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)
	for _, s := range list1 {
		set1[strings.TrimSpace(s)] = true
	}
	for _, s := range list2 {
		set2[strings.TrimSpace(s)] = true
	}

	// Jaccard similarity
	intersection := 0
	for k := range set1 {
		if set2[k] {
			intersection++
		}
	}

	union := len(set1) + len(set2) - intersection
	return float64(intersection) / float64(union)
}

// Helper functions
func min3(a, b, c float64) float64 {
	return math.Min(a, math.Min(b, c))
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
