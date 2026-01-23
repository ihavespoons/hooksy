package ctvp

import (
	"fmt"
	"sort"
)

// Scorer aggregates pairwise similarity scores into a single decision
type Scorer struct {
	config *ThresholdConfig
}

// NewScorer creates a new scorer
func NewScorer(config *ThresholdConfig) *Scorer {
	return &Scorer{
		config: config,
	}
}

// ComputeAggregateScore computes the aggregate score from pairwise comparisons
// using the percentile-based method from the CTVP paper
func (s *Scorer) ComputeAggregateScore(similarities []*SimilarityResult) (float64, map[string]float64) {
	if len(similarities) == 0 {
		return 1.0, nil // No comparisons = assume safe
	}

	// Extract scores
	scores := make([]float64, len(similarities))
	pairwiseMap := make(map[string]float64)

	for i, sim := range similarities {
		scores[i] = sim.Score
		key := fmt.Sprintf("pair_%d", i)
		pairwiseMap[key] = sim.Score
	}

	// Sort scores for percentile calculation
	sorted := make([]float64, len(scores))
	copy(sorted, scores)
	sort.Float64s(sorted)

	// Use 25th percentile as the aggregate (robust to outliers)
	// This means we're concerned if even 25% of pairs show inconsistency
	percentileIdx := len(sorted) / 4
	if percentileIdx >= len(sorted) {
		percentileIdx = len(sorted) - 1
	}
	aggregateScore := sorted[percentileIdx]

	// Also compute min and mean for reference
	pairwiseMap["min"] = sorted[0]
	pairwiseMap["p25"] = aggregateScore
	pairwiseMap["p50"] = sorted[len(sorted)/2]
	pairwiseMap["mean"] = mean(scores)

	return aggregateScore, pairwiseMap
}

// CollectAnomalies aggregates all anomalies from similarity results
func (s *Scorer) CollectAnomalies(similarities []*SimilarityResult) []TraceAnomaly {
	var allAnomalies []TraceAnomaly
	seen := make(map[string]bool)

	for _, sim := range similarities {
		for _, anomaly := range sim.Anomalies {
			// Deduplicate by description
			key := fmt.Sprintf("%s:%s", anomaly.AnomalyType, anomaly.Description)
			if !seen[key] {
				allAnomalies = append(allAnomalies, anomaly)
				seen[key] = true
			}
		}
	}

	// Sort by severity (highest first)
	sort.Slice(allAnomalies, func(i, j int) bool {
		return allAnomalies[i].Severity > allAnomalies[j].Severity
	})

	return allAnomalies
}

// MakeDecision determines the CTVP decision based on aggregate score
func (s *Scorer) MakeDecision(aggregateScore float64, anomalies []TraceAnomaly) (CTVPDecision, string) {
	// Check for critical anomalies first
	for _, anomaly := range anomalies {
		if anomaly.Severity >= 0.95 {
			return DecisionBlock, fmt.Sprintf("Critical anomaly detected: %s", anomaly.Description)
		}
	}

	// Apply threshold-based decision
	if aggregateScore < s.config.DenyThreshold {
		return DecisionDeny, fmt.Sprintf("Score %.2f below deny threshold %.2f", aggregateScore, s.config.DenyThreshold)
	}

	if aggregateScore < s.config.AskThreshold {
		// Count high-severity anomalies
		highSeverity := 0
		for _, a := range anomalies {
			if a.Severity >= 0.7 {
				highSeverity++
			}
		}

		if highSeverity >= 2 {
			return DecisionDeny, fmt.Sprintf("Score %.2f with %d high-severity anomalies", aggregateScore, highSeverity)
		}

		return DecisionAsk, fmt.Sprintf("Score %.2f below ask threshold %.2f", aggregateScore, s.config.AskThreshold)
	}

	return DecisionAllow, fmt.Sprintf("Score %.2f above ask threshold %.2f", aggregateScore, s.config.AskThreshold)
}

// GenerateReasoning creates a human-readable explanation of the decision
func (s *Scorer) GenerateReasoning(result *CTVPResult) string {
	var reasoning string

	reasoning = fmt.Sprintf("CTVP Analysis: %d variants analyzed with aggregate consistency score of %.2f.\n",
		len(result.Variants), result.AggregateScore)

	if len(result.Anomalies) > 0 {
		reasoning += fmt.Sprintf("%d anomalies detected:\n", len(result.Anomalies))
		for i, a := range result.Anomalies {
			if i >= 3 { // Limit to top 3 anomalies
				reasoning += fmt.Sprintf("  ... and %d more\n", len(result.Anomalies)-3)
				break
			}
			reasoning += fmt.Sprintf("  - [%.1f] %s: %s\n", a.Severity, a.AnomalyType, a.Description)
		}
	} else {
		reasoning += "No significant anomalies detected.\n"
	}

	reasoning += fmt.Sprintf("Decision: %s\n", result.Decision)

	return reasoning
}

// ScoreDetails provides detailed scoring breakdown
type ScoreDetails struct {
	AggregateScore     float64            `json:"aggregate_score"`
	Method             string             `json:"method"`
	PairwiseScores     map[string]float64 `json:"pairwise_scores"`
	AnomalyCount       int                `json:"anomaly_count"`
	HighSeverityCount  int                `json:"high_severity_count"`
	DecisionThresholds struct {
		Deny float64 `json:"deny"`
		Ask  float64 `json:"ask"`
	} `json:"decision_thresholds"`
}

// GetScoreDetails returns detailed scoring information
func (s *Scorer) GetScoreDetails(aggregateScore float64, pairwiseScores map[string]float64, anomalies []TraceAnomaly) *ScoreDetails {
	highSeverity := 0
	for _, a := range anomalies {
		if a.Severity >= 0.7 {
			highSeverity++
		}
	}

	details := &ScoreDetails{
		AggregateScore:    aggregateScore,
		Method:            "percentile_25",
		PairwiseScores:    pairwiseScores,
		AnomalyCount:      len(anomalies),
		HighSeverityCount: highSeverity,
	}
	details.DecisionThresholds.Deny = s.config.DenyThreshold
	details.DecisionThresholds.Ask = s.config.AskThreshold

	return details
}

// Helper function
func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
