package ctvp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/ihavespoons/hooksy/internal/logger"
)

// Analyzer is the main CTVP analysis coordinator
type Analyzer struct {
	config            *Config
	orbitGenerator    *OrbitGenerator
	tracePredictor    *TracePredictor
	similarityCalc    *SimilarityCalculator
	scorer            *Scorer
	thresholdManager  *ThresholdManager

	// Cache for analysis results
	cache     map[string]*cacheEntry
	cacheMu   sync.RWMutex

	// Compiled trigger patterns
	triggerPatterns []*compiledTrigger

	// Metrics
	metrics   *AnalysisMetrics
	metricsMu sync.Mutex
}

type compiledTrigger struct {
	patterns    []*regexp.Regexp
	minCodeSize int
	languages   []string
	mode        Mode
}

type cacheEntry struct {
	result    *CTVPResult
	timestamp time.Time
}

// NewAnalyzer creates a new CTVP analyzer
func NewAnalyzer(config *Config, llmClient LLMClient) *Analyzer {
	// Determine state path for threshold persistence
	homeDir, _ := os.UserHomeDir()
	statePath := filepath.Join(homeDir, ".hooksy", "ctvp", "threshold_state.json")

	a := &Analyzer{
		config:           config,
		orbitGenerator:   NewOrbitGenerator(&config.Orbit),
		tracePredictor:   NewTracePredictor(&config.Trace, llmClient),
		similarityCalc:   NewSimilarityCalculator(&config.Similarity),
		scorer:           NewScorer(&config.Threshold),
		thresholdManager: NewThresholdManager(&config.Threshold, statePath),
		cache:            make(map[string]*cacheEntry),
		metrics: &AnalysisMetrics{
			DecisionCounts: make(map[CTVPDecision]int64),
			LastReset:      time.Now(),
		},
	}

	// Compile trigger patterns
	a.compileTriggers()

	return a
}

// compileTriggers pre-compiles regex patterns for triggers
func (a *Analyzer) compileTriggers() {
	a.triggerPatterns = make([]*compiledTrigger, len(a.config.Triggers))

	for i, trigger := range a.config.Triggers {
		ct := &compiledTrigger{
			patterns:    make([]*regexp.Regexp, 0, len(trigger.ToolNames)),
			minCodeSize: trigger.MinCodeSize,
			languages:   trigger.Languages,
			mode:        trigger.Mode,
		}

		for _, pattern := range trigger.ToolNames {
			if re, err := regexp.Compile(pattern); err == nil {
				ct.patterns = append(ct.patterns, re)
			} else {
				logger.Warn().
					Str("pattern", pattern).
					Err(err).
					Msg("Failed to compile CTVP trigger pattern")
			}
		}

		a.triggerPatterns[i] = ct
	}
}

// ShouldAnalyze determines if CTVP analysis should be performed
func (a *Analyzer) ShouldAnalyze(toolName string, code string) bool {
	if !a.config.Enabled {
		return false
	}

	codeSize := len(code)

	for _, trigger := range a.triggerPatterns {
		// Check tool name
		nameMatches := false
		for _, pattern := range trigger.patterns {
			if pattern.MatchString(toolName) {
				nameMatches = true
				break
			}
		}

		if !nameMatches {
			continue
		}

		// Check code size
		if codeSize < trigger.minCodeSize {
			continue
		}

		// Check language if specified
		if len(trigger.languages) > 0 {
			lang := a.orbitGenerator.detectLanguage(code)
			langMatches := false
			for _, l := range trigger.languages {
				if l == lang {
					langMatches = true
					break
				}
			}
			if !langMatches {
				continue
			}
		}

		return true
	}

	return false
}

// Analyze performs CTVP analysis on the given code
func (a *Analyzer) Analyze(ctx context.Context, code string, toolName string) (*CTVPResult, error) {
	startTime := time.Now()

	// Check cache first
	cacheKey := a.cacheKey(code, toolName)
	if result := a.checkCache(cacheKey); result != nil {
		result.Cached = true
		a.updateMetrics(result, true)
		return result, nil
	}

	// Apply timeout
	ctx, cancel := context.WithTimeout(ctx, a.config.Timeout)
	defer cancel()

	result := &CTVPResult{
		OriginalCode: code,
		ToolName:     toolName,
	}

	// Step 1: Generate semantic orbit
	orbit, err := a.orbitGenerator.Generate(code)
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to generate semantic orbit")
		// If orbit generation fails, we can't do CTVP - return allow with warning
		result.Decision = DecisionAllow
		result.Reasoning = fmt.Sprintf("Orbit generation failed: %v", err)
		result.AggregateScore = 1.0
		result.AnalysisTime = time.Since(startTime)
		return result, nil
	}
	result.Variants = orbit.Variants

	logger.Debug().
		Int("variants", len(orbit.Variants)).
		Str("language", orbit.Language).
		Msg("Generated semantic orbit")

	// Step 2: Predict traces for each variant
	traces, err := a.tracePredictor.PredictTraces(ctx, orbit)
	if err != nil {
		logger.Warn().Err(err).Msg("Trace prediction encountered errors")
		// Continue with whatever traces we got
	}
	result.Traces = traces

	// Check if we have enough successful traces
	successfulTraces := 0
	for _, t := range traces {
		if t.Error == "" {
			successfulTraces++
		}
	}
	if successfulTraces < a.config.Orbit.MinSize {
		result.Decision = DecisionAllow
		result.Reasoning = fmt.Sprintf("Insufficient successful trace predictions: %d of %d", successfulTraces, len(traces))
		result.AggregateScore = 1.0
		result.AnalysisTime = time.Since(startTime)
		return result, nil
	}

	// Step 3: Compute pairwise similarities
	similarities := a.computePairwiseSimilarities(traces)

	// Step 4: Aggregate scores
	aggregateScore, pairwiseScores := a.scorer.ComputeAggregateScore(similarities)
	result.AggregateScore = aggregateScore
	result.PairwiseScores = pairwiseScores

	// Step 5: Collect anomalies
	result.Anomalies = a.scorer.CollectAnomalies(similarities)

	// Step 6: Make decision using adaptive thresholds
	denyThreshold, askThreshold := a.thresholdManager.GetThresholds()
	tempConfig := &ThresholdConfig{
		DenyThreshold: denyThreshold,
		AskThreshold:  askThreshold,
	}
	tempScorer := NewScorer(tempConfig)
	result.Decision, result.Reasoning = tempScorer.MakeDecision(aggregateScore, result.Anomalies)

	// Generate detailed reasoning
	result.Reasoning = a.scorer.GenerateReasoning(result)
	result.AnalysisTime = time.Since(startTime)

	// Cache the result
	a.cacheResult(cacheKey, result)

	// Update metrics
	a.updateMetrics(result, false)

	logger.Info().
		Float64("score", aggregateScore).
		Str("decision", string(result.Decision)).
		Int("anomalies", len(result.Anomalies)).
		Dur("duration", result.AnalysisTime).
		Msg("CTVP analysis complete")

	return result, nil
}

// computePairwiseSimilarities computes similarity for all trace pairs
func (a *Analyzer) computePairwiseSimilarities(traces []*ExecutionTrace) []*SimilarityResult {
	var similarities []*SimilarityResult

	// Compare each pair
	for i := 0; i < len(traces); i++ {
		for j := i + 1; j < len(traces); j++ {
			sim := a.similarityCalc.ComputeSimilarity(traces[i], traces[j])
			sim.Anomalies = a.enrichAnomalies(sim.Anomalies, traces[i].VariantID, traces[j].VariantID)
			similarities = append(similarities, sim)
		}
	}

	return similarities
}

// enrichAnomalies adds variant IDs to anomalies
func (a *Analyzer) enrichAnomalies(anomalies []TraceAnomaly, variantA, variantB string) []TraceAnomaly {
	for i := range anomalies {
		if anomalies[i].VariantA == "" {
			anomalies[i].VariantA = variantA
		}
		if anomalies[i].VariantB == "" {
			anomalies[i].VariantB = variantB
		}
	}
	return anomalies
}

// cacheKey generates a cache key for the analysis
func (a *Analyzer) cacheKey(code, toolName string) string {
	hash := sha256.Sum256([]byte(code + toolName))
	return hex.EncodeToString(hash[:])
}

// checkCache returns a cached result if available and not expired
func (a *Analyzer) checkCache(key string) *CTVPResult {
	if !a.config.Cache.Enabled {
		return nil
	}

	a.cacheMu.RLock()
	entry, ok := a.cache[key]
	a.cacheMu.RUnlock()

	if !ok {
		return nil
	}

	// Check if expired
	if time.Since(entry.timestamp) > a.config.Cache.TTL {
		a.cacheMu.Lock()
		delete(a.cache, key)
		a.cacheMu.Unlock()
		return nil
	}

	return entry.result
}

// cacheResult stores a result in the cache
func (a *Analyzer) cacheResult(key string, result *CTVPResult) {
	if !a.config.Cache.Enabled {
		return
	}

	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()

	// Prune cache if too large
	if len(a.cache) >= a.config.Cache.MaxEntries {
		// Simple eviction: remove oldest 10%
		toRemove := a.config.Cache.MaxEntries / 10
		for k := range a.cache {
			if toRemove <= 0 {
				break
			}
			delete(a.cache, k)
			toRemove--
		}
	}

	a.cache[key] = &cacheEntry{
		result:    result,
		timestamp: time.Now(),
	}
}

// updateMetrics updates analysis metrics
func (a *Analyzer) updateMetrics(result *CTVPResult, cached bool) {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()

	a.metrics.TotalAnalyses++
	a.metrics.DecisionCounts[result.Decision]++

	// Update running average of scores
	n := float64(a.metrics.TotalAnalyses)
	a.metrics.AverageScore = a.metrics.AverageScore*(n-1)/n + result.AggregateScore/n

	// Update average analysis time
	a.metrics.AverageAnalysisTime = time.Duration(
		float64(a.metrics.AverageAnalysisTime)*(n-1)/n + float64(result.AnalysisTime)/n,
	)

	// Update cache hit rate
	if cached {
		a.metrics.CacheHitRate = a.metrics.CacheHitRate*(n-1)/n + 1/n
	} else {
		a.metrics.CacheHitRate = a.metrics.CacheHitRate * (n - 1) / n
	}
}

// GetMetrics returns a copy of current metrics
func (a *Analyzer) GetMetrics() *AnalysisMetrics {
	a.metricsMu.Lock()
	defer a.metricsMu.Unlock()

	// Return a copy
	counts := make(map[CTVPDecision]int64)
	for k, v := range a.metrics.DecisionCounts {
		counts[k] = v
	}

	return &AnalysisMetrics{
		TotalAnalyses:       a.metrics.TotalAnalyses,
		AverageScore:        a.metrics.AverageScore,
		DecisionCounts:      counts,
		AverageAnalysisTime: a.metrics.AverageAnalysisTime,
		CacheHitRate:        a.metrics.CacheHitRate,
		ErrorRate:           a.metrics.ErrorRate,
		LastReset:           a.metrics.LastReset,
	}
}

// GetThresholdState returns current threshold state
func (a *Analyzer) GetThresholdState() *ThresholdState {
	return a.thresholdManager.GetState()
}

// ProvideFeedback records user feedback for threshold adaptation
func (a *Analyzer) ProvideFeedback(score float64, wasCorrect bool, wasPositive bool) {
	a.thresholdManager.ProvideFeedback(score, wasCorrect, wasPositive)
}

// ResetThresholds resets thresholds to defaults
func (a *Analyzer) ResetThresholds() {
	a.thresholdManager.Reset()
}

// ClearCache clears the result cache
func (a *Analyzer) ClearCache() {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	a.cache = make(map[string]*cacheEntry)
}
