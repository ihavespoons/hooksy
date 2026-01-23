// Package ctvp implements Cross-Trace Verification Protocol for detecting backdoors
// in code-generating LLMs by analyzing consistency of execution trace predictions
// across semantically equivalent code variants.
//
// Based on arXiv 2512.13821 - backdoored models show inconsistent trace predictions
// across semantically equivalent code variants, while benign models remain consistent.
package ctvp

import (
	"time"
)

// TransformationType represents a semantic-preserving code transformation
type TransformationType string

const (
	TransformVariableRename    TransformationType = "variable_rename"
	TransformDeadCodeInjection TransformationType = "dead_code_injection"
	TransformStatementReorder  TransformationType = "statement_reorder"
	TransformReformat          TransformationType = "reformat"
	TransformCommentModify     TransformationType = "comment_modify"
)

// AllTransformations returns all available transformation types
func AllTransformations() []TransformationType {
	return []TransformationType{
		TransformVariableRename,
		TransformDeadCodeInjection,
		TransformStatementReorder,
		TransformReformat,
		TransformCommentModify,
	}
}

// CodeVariant represents a semantically equivalent version of code
type CodeVariant struct {
	// ID uniquely identifies this variant
	ID string `json:"id"`

	// OriginalCode is the unmodified source code
	OriginalCode string `json:"original_code"`

	// TransformedCode is the code after transformation
	TransformedCode string `json:"transformed_code"`

	// TransformType indicates which transformation was applied
	TransformType TransformationType `json:"transform_type"`

	// TransformDetails contains transformation-specific metadata
	TransformDetails map[string]string `json:"transform_details,omitempty"`
}

// TraceStep represents a single step in an execution trace
type TraceStep struct {
	// Line is the line number being executed
	Line int `json:"line"`

	// Operation describes what operation is being performed
	Operation string `json:"operation"`

	// Variables maps variable names to their values at this step
	Variables map[string]interface{} `json:"variables,omitempty"`

	// SideEffects lists any side effects (file writes, network calls, etc)
	SideEffects []string `json:"side_effects,omitempty"`
}

// TraceState represents the final state after execution
type TraceState struct {
	// Variables maps variable names to their final values
	Variables map[string]interface{} `json:"variables,omitempty"`

	// Outputs lists any outputs produced (stdout, return values, etc)
	Outputs []string `json:"outputs,omitempty"`

	// Errors lists any errors that occurred
	Errors []string `json:"errors,omitempty"`
}

// ExecutionTrace represents an LLM-predicted execution trace for a code variant
type ExecutionTrace struct {
	// VariantID links back to the code variant
	VariantID string `json:"variant_id"`

	// Steps is the sequence of execution steps
	Steps []TraceStep `json:"steps"`

	// FinalState is the state after execution completes
	FinalState TraceState `json:"final_state"`

	// Confidence is the LLM's confidence in this prediction (0-1)
	Confidence float32 `json:"confidence"`

	// Error indicates if trace prediction failed
	Error string `json:"error,omitempty"`

	// PredictionTime is how long the prediction took
	PredictionTime time.Duration `json:"prediction_time"`
}

// CTVPDecision represents the decision from CTVP analysis
type CTVPDecision string

const (
	DecisionAllow CTVPDecision = "allow" // Code appears safe
	DecisionAsk   CTVPDecision = "ask"   // Uncertain, prompt user
	DecisionDeny  CTVPDecision = "deny"  // Suspicious patterns detected
	DecisionBlock CTVPDecision = "block" // High confidence backdoor
)

// TraceAnomaly describes a detected inconsistency between trace predictions
type TraceAnomaly struct {
	// VariantA is the first variant in the comparison
	VariantA string `json:"variant_a"`

	// VariantB is the second variant in the comparison
	VariantB string `json:"variant_b"`

	// AnomalyType categorizes the inconsistency
	AnomalyType string `json:"anomaly_type"`

	// Description explains the anomaly in detail
	Description string `json:"description"`

	// Severity is how concerning this anomaly is (0-1)
	Severity float64 `json:"severity"`

	// Evidence contains specific data supporting the anomaly
	Evidence map[string]interface{} `json:"evidence,omitempty"`
}

// CTVPResult is the outcome of CTVP analysis
type CTVPResult struct {
	// AggregateScore is the overall consistency score (0-1, lower = more suspicious)
	AggregateScore float64 `json:"aggregate_score"`

	// Decision is the resulting security decision
	Decision CTVPDecision `json:"decision"`

	// Anomalies lists detected inconsistencies between trace predictions
	Anomalies []TraceAnomaly `json:"anomalies,omitempty"`

	// Reasoning explains how the decision was reached
	Reasoning string `json:"reasoning"`

	// PairwiseScores contains consistency scores for each variant pair
	PairwiseScores map[string]float64 `json:"pairwise_scores,omitempty"`

	// Variants contains the code variants analyzed
	Variants []*CodeVariant `json:"variants,omitempty"`

	// Traces contains the predicted execution traces
	Traces []*ExecutionTrace `json:"traces,omitempty"`

	// AnalysisTime is how long the full analysis took
	AnalysisTime time.Duration `json:"analysis_time"`

	// Cached indicates if this result came from cache
	Cached bool `json:"cached"`

	// OriginalCode is the code that was analyzed
	OriginalCode string `json:"original_code,omitempty"`

	// ToolName is the tool that triggered analysis
	ToolName string `json:"tool_name,omitempty"`
}

// SemanticOrbit represents a set of semantically equivalent code variants
type SemanticOrbit struct {
	// OriginalCode is the starting code
	OriginalCode string `json:"original_code"`

	// Variants are the transformed versions
	Variants []*CodeVariant `json:"variants"`

	// Language is the detected or specified language
	Language string `json:"language,omitempty"`

	// GenerationTime is how long orbit generation took
	GenerationTime time.Duration `json:"generation_time"`
}

// SimilarityResult contains the result of comparing two execution traces
type SimilarityResult struct {
	// Score is the overall similarity (0-1, higher = more similar)
	Score float64 `json:"score"`

	// StepAlignment measures how well execution steps align
	StepAlignment float64 `json:"step_alignment"`

	// StateMatch measures how well final states match
	StateMatch float64 `json:"state_match"`

	// OutputMatch measures how well outputs match
	OutputMatch float64 `json:"output_match"`

	// Anomalies lists specific inconsistencies found
	Anomalies []TraceAnomaly `json:"anomalies,omitempty"`
}

// ThresholdState tracks adaptive threshold adjustments
type ThresholdState struct {
	// DenyThreshold is the score below which to deny
	DenyThreshold float64 `json:"deny_threshold"`

	// AskThreshold is the score below which to ask (above deny)
	AskThreshold float64 `json:"ask_threshold"`

	// FalsePositiveRate is the estimated FPR
	FalsePositiveRate float64 `json:"false_positive_rate"`

	// TruePositiveRate is the estimated TPR
	TruePositiveRate float64 `json:"true_positive_rate"`

	// SampleCount is how many samples contributed to these estimates
	SampleCount int `json:"sample_count"`

	// LastUpdated is when the threshold was last adjusted
	LastUpdated time.Time `json:"last_updated"`
}

// AnalysisMetrics tracks performance and accuracy metrics
type AnalysisMetrics struct {
	// TotalAnalyses is the count of analyses performed
	TotalAnalyses int64 `json:"total_analyses"`

	// AverageScore is the mean aggregate score
	AverageScore float64 `json:"average_score"`

	// DecisionCounts maps decisions to their counts
	DecisionCounts map[CTVPDecision]int64 `json:"decision_counts"`

	// AverageAnalysisTime is the mean analysis duration
	AverageAnalysisTime time.Duration `json:"average_analysis_time"`

	// CacheHitRate is the fraction of requests served from cache
	CacheHitRate float64 `json:"cache_hit_rate"`

	// ErrorRate is the fraction of analyses that failed
	ErrorRate float64 `json:"error_rate"`

	// LastReset is when metrics were last reset
	LastReset time.Time `json:"last_reset"`
}

// HistoryEntry records a single CTVP analysis for historical review
type HistoryEntry struct {
	// ID uniquely identifies this entry
	ID int64 `json:"id"`

	// SessionID links to the hooksy session
	SessionID string `json:"session_id"`

	// Timestamp is when the analysis occurred
	Timestamp time.Time `json:"timestamp"`

	// ToolName is the tool that triggered analysis
	ToolName string `json:"tool_name"`

	// CodeHash is a hash of the analyzed code
	CodeHash string `json:"code_hash"`

	// Result is the analysis outcome
	Result *CTVPResult `json:"result"`
}
