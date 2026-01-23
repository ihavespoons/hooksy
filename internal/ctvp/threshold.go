package ctvp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ihavespoons/hooksy/internal/logger"
)

// ThresholdManager handles adaptive threshold adjustment
type ThresholdManager struct {
	config *ThresholdConfig
	state  *ThresholdState
	mu     sync.RWMutex

	// Historical samples for threshold adaptation
	samples []adaptationSample

	// Path for persistence
	statePath string
}

type adaptationSample struct {
	Score      float64
	Feedback   FeedbackType
	Timestamp  time.Time
}

// FeedbackType represents user feedback on a decision
type FeedbackType string

const (
	FeedbackTruePositive  FeedbackType = "true_positive"  // Correctly flagged as suspicious
	FeedbackFalsePositive FeedbackType = "false_positive" // Incorrectly flagged as suspicious
	FeedbackTrueNegative  FeedbackType = "true_negative"  // Correctly allowed
	FeedbackFalseNegative FeedbackType = "false_negative" // Incorrectly allowed (should have flagged)
)

// NewThresholdManager creates a new threshold manager
func NewThresholdManager(config *ThresholdConfig, statePath string) *ThresholdManager {
	tm := &ThresholdManager{
		config: config,
		state: &ThresholdState{
			DenyThreshold: config.DenyThreshold,
			AskThreshold:  config.AskThreshold,
			LastUpdated:   time.Now(),
		},
		samples:   make([]adaptationSample, 0),
		statePath: statePath,
	}

	// Try to load persisted state
	if statePath != "" {
		if err := tm.loadState(); err != nil {
			logger.Debug().Err(err).Msg("Could not load threshold state, using defaults")
		}
	}

	return tm
}

// GetThresholds returns the current thresholds
func (tm *ThresholdManager) GetThresholds() (denyThreshold, askThreshold float64) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.state.DenyThreshold, tm.state.AskThreshold
}

// GetState returns a copy of the current threshold state
func (tm *ThresholdManager) GetState() *ThresholdState {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	// Return a copy
	return &ThresholdState{
		DenyThreshold:     tm.state.DenyThreshold,
		AskThreshold:      tm.state.AskThreshold,
		FalsePositiveRate: tm.state.FalsePositiveRate,
		TruePositiveRate:  tm.state.TruePositiveRate,
		SampleCount:       tm.state.SampleCount,
		LastUpdated:       tm.state.LastUpdated,
	}
}

// RecordSample adds a new sample for threshold adaptation
func (tm *ThresholdManager) RecordSample(score float64, feedback FeedbackType) {
	if !tm.config.Adaptive {
		return
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	sample := adaptationSample{
		Score:     score,
		Feedback:  feedback,
		Timestamp: time.Now(),
	}
	tm.samples = append(tm.samples, sample)
	tm.state.SampleCount++

	// Prune old samples (keep last 1000)
	if len(tm.samples) > 1000 {
		tm.samples = tm.samples[len(tm.samples)-1000:]
	}

	// Update rates
	tm.updateRates()

	// Maybe adapt thresholds
	if tm.state.SampleCount >= tm.config.MinSamples && tm.state.SampleCount%10 == 0 {
		tm.adaptThresholds()
	}
}

// updateRates recalculates FPR and TPR from samples
func (tm *ThresholdManager) updateRates() {
	if len(tm.samples) == 0 {
		return
	}

	var tp, fp, tn, fn int
	for _, s := range tm.samples {
		switch s.Feedback {
		case FeedbackTruePositive:
			tp++
		case FeedbackFalsePositive:
			fp++
		case FeedbackTrueNegative:
			tn++
		case FeedbackFalseNegative:
			fn++
		}
	}

	// Calculate rates
	if fp+tn > 0 {
		tm.state.FalsePositiveRate = float64(fp) / float64(fp+tn)
	}
	if tp+fn > 0 {
		tm.state.TruePositiveRate = float64(tp) / float64(tp+fn)
	}
}

// adaptThresholds adjusts thresholds based on observed performance
func (tm *ThresholdManager) adaptThresholds() {
	currentFPR := tm.state.FalsePositiveRate
	targetFPR := tm.config.TargetFPR
	rate := tm.config.AdaptationRate

	if currentFPR <= 0 || len(tm.samples) < tm.config.MinSamples {
		return
	}

	// If FPR is too high, raise thresholds (less sensitive)
	// If FPR is too low, lower thresholds (more sensitive)
	adjustment := 0.0
	if currentFPR > targetFPR*1.5 {
		// FPR too high - be less sensitive
		adjustment = rate * (currentFPR - targetFPR)
	} else if currentFPR < targetFPR*0.5 {
		// FPR very low - could be more sensitive
		adjustment = -rate * (targetFPR - currentFPR)
	}

	if adjustment != 0 {
		newDeny := clamp(tm.state.DenyThreshold+adjustment, 0.1, 0.5)
		newAsk := clamp(tm.state.AskThreshold+adjustment, newDeny+0.1, 0.8)

		logger.Info().
			Float64("old_deny", tm.state.DenyThreshold).
			Float64("new_deny", newDeny).
			Float64("old_ask", tm.state.AskThreshold).
			Float64("new_ask", newAsk).
			Float64("current_fpr", currentFPR).
			Float64("target_fpr", targetFPR).
			Msg("Adapting CTVP thresholds")

		tm.state.DenyThreshold = newDeny
		tm.state.AskThreshold = newAsk
		tm.state.LastUpdated = time.Now()

		// Persist state
		if tm.statePath != "" {
			if err := tm.saveState(); err != nil {
				logger.Warn().Err(err).Msg("Failed to save threshold state")
			}
		}
	}
}

// clamp constrains a value to a range
func clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// loadState loads persisted threshold state from disk
func (tm *ThresholdManager) loadState() error {
	data, err := os.ReadFile(tm.statePath)
	if err != nil {
		return err
	}

	var state ThresholdState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}

	tm.state = &state
	logger.Debug().
		Float64("deny", state.DenyThreshold).
		Float64("ask", state.AskThreshold).
		Int("samples", state.SampleCount).
		Msg("Loaded threshold state")

	return nil
}

// saveState persists threshold state to disk
func (tm *ThresholdManager) saveState() error {
	data, err := json.MarshalIndent(tm.state, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	dir := filepath.Dir(tm.statePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(tm.statePath, data, 0644)
}

// Reset resets thresholds to configured defaults
func (tm *ThresholdManager) Reset() {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.state = &ThresholdState{
		DenyThreshold: tm.config.DenyThreshold,
		AskThreshold:  tm.config.AskThreshold,
		LastUpdated:   time.Now(),
	}
	tm.samples = make([]adaptationSample, 0)

	logger.Info().Msg("Reset CTVP thresholds to defaults")

	if tm.statePath != "" {
		if err := tm.saveState(); err != nil {
			logger.Warn().Err(err).Msg("Failed to save reset threshold state")
		}
	}
}

// ProvideFeedback allows external feedback on decisions
func (tm *ThresholdManager) ProvideFeedback(score float64, wasCorrect bool, wasPositive bool) {
	var feedback FeedbackType
	if wasPositive {
		if wasCorrect {
			feedback = FeedbackTruePositive
		} else {
			feedback = FeedbackFalsePositive
		}
	} else {
		if wasCorrect {
			feedback = FeedbackTrueNegative
		} else {
			feedback = FeedbackFalseNegative
		}
	}

	tm.RecordSample(score, feedback)
}
