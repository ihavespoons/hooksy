package ctvp

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/ihavespoons/hooksy/internal/logger"
)

// TracePredictor predicts execution traces using an LLM
type TracePredictor struct {
	config    *TraceConfig
	llmClient LLMClient
}

// LLMClient interface for LLM interactions (to be implemented by llm package adapter)
type LLMClient interface {
	// Complete sends a prompt to the LLM and returns the response
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

// NewTracePredictor creates a new trace predictor
func NewTracePredictor(config *TraceConfig, client LLMClient) *TracePredictor {
	return &TracePredictor{
		config:    config,
		llmClient: client,
	}
}

// PredictTrace predicts the execution trace for a single code variant
func (p *TracePredictor) PredictTrace(ctx context.Context, variant *CodeVariant) (*ExecutionTrace, error) {
	startTime := time.Now()

	trace := &ExecutionTrace{
		VariantID: variant.ID,
	}

	// Format the prompt
	prompt := fmt.Sprintf(TracePredictionPrompt, variant.TransformedCode)

	// Call the LLM
	response, err := p.llmClient.Complete(ctx, TracePredictionSystemPrompt, prompt)
	if err != nil {
		trace.Error = fmt.Sprintf("LLM call failed: %v", err)
		trace.PredictionTime = time.Since(startTime)
		return trace, err
	}

	// Parse the response
	if err := p.parseTraceResponse(response, trace); err != nil {
		trace.Error = fmt.Sprintf("Failed to parse response: %v", err)
		trace.PredictionTime = time.Since(startTime)
		return trace, err
	}

	// Truncate steps if needed
	if p.config.MaxSteps > 0 && len(trace.Steps) > p.config.MaxSteps {
		trace.Steps = trace.Steps[:p.config.MaxSteps]
	}

	trace.PredictionTime = time.Since(startTime)

	logger.Debug().
		Str("variant_id", variant.ID).
		Int("steps", len(trace.Steps)).
		Float32("confidence", trace.Confidence).
		Dur("duration", trace.PredictionTime).
		Msg("Predicted trace")

	return trace, nil
}

// PredictTraces predicts traces for all variants in an orbit
func (p *TracePredictor) PredictTraces(ctx context.Context, orbit *SemanticOrbit) ([]*ExecutionTrace, error) {
	if !p.config.Parallel {
		return p.predictTracesSequential(ctx, orbit)
	}
	return p.predictTracesParallel(ctx, orbit)
}

func (p *TracePredictor) predictTracesSequential(ctx context.Context, orbit *SemanticOrbit) ([]*ExecutionTrace, error) {
	traces := make([]*ExecutionTrace, 0, len(orbit.Variants))

	for _, variant := range orbit.Variants {
		select {
		case <-ctx.Done():
			return traces, ctx.Err()
		default:
		}

		trace, err := p.PredictTrace(ctx, variant)
		if err != nil {
			logger.Warn().
				Err(err).
				Str("variant_id", variant.ID).
				Msg("Failed to predict trace")
			// Continue with other variants
		}
		traces = append(traces, trace)
	}

	return traces, nil
}

func (p *TracePredictor) predictTracesParallel(ctx context.Context, orbit *SemanticOrbit) ([]*ExecutionTrace, error) {
	traces := make([]*ExecutionTrace, len(orbit.Variants))
	var wg sync.WaitGroup
	sem := make(chan struct{}, p.config.MaxParallel)
	var mu sync.Mutex
	var firstErr error

	for i, variant := range orbit.Variants {
		wg.Add(1)
		go func(idx int, v *CodeVariant) {
			defer wg.Done()

			// Acquire semaphore
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				if firstErr == nil {
					firstErr = ctx.Err()
				}
				mu.Unlock()
				return
			}

			trace, err := p.PredictTrace(ctx, v)
			if err != nil {
				logger.Warn().
					Err(err).
					Str("variant_id", v.ID).
					Msg("Failed to predict trace")
			}

			mu.Lock()
			traces[idx] = trace
			if err != nil && firstErr == nil {
				firstErr = err
			}
			mu.Unlock()
		}(i, variant)
	}

	wg.Wait()

	// Filter out nil traces (shouldn't happen but be safe)
	result := make([]*ExecutionTrace, 0, len(traces))
	for _, t := range traces {
		if t != nil {
			result = append(result, t)
		}
	}

	return result, firstErr
}

// parseTraceResponse parses the LLM response into an ExecutionTrace
func (p *TracePredictor) parseTraceResponse(response string, trace *ExecutionTrace) error {
	// Try to extract JSON from the response
	jsonStr := extractJSON(response)
	if jsonStr == "" {
		return fmt.Errorf("no JSON found in response")
	}

	// Parse into a temporary structure
	var parsed struct {
		Steps []struct {
			Line        int                    `json:"line"`
			Operation   string                 `json:"operation"`
			Variables   map[string]interface{} `json:"variables"`
			SideEffects []string               `json:"side_effects"`
		} `json:"steps"`
		FinalState struct {
			Variables map[string]interface{} `json:"variables"`
			Outputs   []string               `json:"outputs"`
			Errors    []string               `json:"errors"`
		} `json:"final_state"`
		Confidence float32 `json:"confidence"`
	}

	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		return fmt.Errorf("JSON parse error: %w", err)
	}

	// Convert to our types
	trace.Steps = make([]TraceStep, len(parsed.Steps))
	for i, step := range parsed.Steps {
		trace.Steps[i] = TraceStep{
			Line:        step.Line,
			Operation:   step.Operation,
			Variables:   step.Variables,
			SideEffects: step.SideEffects,
		}
	}

	trace.FinalState = TraceState{
		Variables: parsed.FinalState.Variables,
		Outputs:   parsed.FinalState.Outputs,
		Errors:    parsed.FinalState.Errors,
	}

	trace.Confidence = parsed.Confidence

	return nil
}

// extractJSON attempts to extract a JSON object from a string
func extractJSON(s string) string {
	// Find the first { and last }
	start := -1
	end := -1
	depth := 0

	for i, c := range s {
		if c == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if c == '}' {
			depth--
			if depth == 0 {
				end = i + 1
				break
			}
		}
	}

	if start >= 0 && end > start {
		return s[start:end]
	}

	return ""
}

// MockLLMClient is a mock implementation for testing
type MockLLMClient struct {
	Response string
	Err      error
}

func (m *MockLLMClient) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	if m.Err != nil {
		return "", m.Err
	}
	return m.Response, nil
}
