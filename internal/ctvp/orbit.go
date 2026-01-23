package ctvp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ihavespoons/hooksy/internal/logger"
)

// OrbitGenerator creates semantic orbits of code variants
type OrbitGenerator struct {
	registry *TransformerRegistry
	config   *OrbitConfig
}

// NewOrbitGenerator creates a new orbit generator
func NewOrbitGenerator(config *OrbitConfig) *OrbitGenerator {
	return &OrbitGenerator{
		registry: NewTransformerRegistry(),
		config:   config,
	}
}

// Generate creates a semantic orbit for the given code
func (g *OrbitGenerator) Generate(code string) (*SemanticOrbit, error) {
	startTime := time.Now()

	orbit := &SemanticOrbit{
		OriginalCode: code,
		Variants:     make([]*CodeVariant, 0, g.config.Size),
		Language:     g.detectLanguage(code),
	}

	// Add the original code as the first variant
	originalVariant := &CodeVariant{
		ID:              g.generateVariantID(code, "original"),
		OriginalCode:    code,
		TransformedCode: code,
		TransformType:   "original",
	}
	orbit.Variants = append(orbit.Variants, originalVariant)

	// Generate transformed variants
	transformsUsed := make(map[TransformationType]bool)
	attempts := 0
	maxAttempts := g.config.MaxTransformAttempts * len(g.config.Transformations)

	for len(orbit.Variants) < g.config.Size && attempts < maxAttempts {
		attempts++

		// Select a transformation type we haven't used yet, or cycle back
		var selectedType TransformationType
		for _, t := range g.config.Transformations {
			if !transformsUsed[t] {
				selectedType = t
				break
			}
		}

		// If all transformations have been used once, allow reuse
		if selectedType == "" {
			idx := (len(orbit.Variants) - 1) % len(g.config.Transformations)
			selectedType = g.config.Transformations[idx]
		}

		transformer, ok := g.registry.Get(selectedType)
		if !ok {
			logger.Debug().Str("type", string(selectedType)).Msg("No transformer for type")
			continue
		}

		if !transformer.CanTransform(code) {
			logger.Debug().Str("type", string(selectedType)).Msg("Transformer cannot handle code")
			continue
		}

		transformed, details, err := transformer.Transform(code)
		if err != nil {
			logger.Debug().Err(err).Str("type", string(selectedType)).Msg("Transform failed")
			continue
		}

		// Skip if transformation produced identical code
		if transformed == code {
			logger.Debug().Str("type", string(selectedType)).Msg("Transform produced identical code")
			continue
		}

		// Skip if we already have this exact variant
		if g.isDuplicate(orbit.Variants, transformed) {
			logger.Debug().Str("type", string(selectedType)).Msg("Duplicate variant")
			continue
		}

		variant := &CodeVariant{
			ID:               g.generateVariantID(transformed, string(selectedType)),
			OriginalCode:     code,
			TransformedCode:  transformed,
			TransformType:    selectedType,
			TransformDetails: details,
		}
		orbit.Variants = append(orbit.Variants, variant)
		transformsUsed[selectedType] = true

		logger.Debug().
			Str("type", string(selectedType)).
			Int("variant_count", len(orbit.Variants)).
			Msg("Generated variant")
	}

	orbit.GenerationTime = time.Since(startTime)

	// Validate we have enough variants
	if len(orbit.Variants) < g.config.MinSize {
		return orbit, fmt.Errorf("insufficient variants: got %d, need %d", len(orbit.Variants), g.config.MinSize)
	}

	logger.Debug().
		Int("variants", len(orbit.Variants)).
		Dur("duration", orbit.GenerationTime).
		Msg("Generated semantic orbit")

	return orbit, nil
}

// detectLanguage attempts to detect the programming language
func (g *OrbitGenerator) detectLanguage(code string) string {
	// Simple heuristics
	switch {
	case containsAny(code, "#!/bin/bash", "#!/bin/sh", "#!/usr/bin/env bash"):
		return "shell"
	case containsAny(code, "def ", "import ", "from ") && containsAny(code, ":"):
		return "python"
	case containsAny(code, "package ", "func ") && containsAny(code, "import"):
		return "go"
	case containsAny(code, "function", "const ", "let ", "var ") && containsAny(code, "=>", "==="):
		return "javascript"
	case containsAny(code, "fn ", "let mut", "impl "):
		return "rust"
	case containsAny(code, "public class", "private ", "public static"):
		return "java"
	default:
		return "unknown"
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, substr := range substrs {
		if containsString(s, substr) {
			return true
		}
	}
	return false
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && findString(s, substr) >= 0
}

func findString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// generateVariantID creates a unique ID for a variant
func (g *OrbitGenerator) generateVariantID(code string, transformType string) string {
	hash := sha256.Sum256([]byte(code + transformType))
	return hex.EncodeToString(hash[:8])
}

// isDuplicate checks if the transformed code already exists in the variants
func (g *OrbitGenerator) isDuplicate(variants []*CodeVariant, code string) bool {
	for _, v := range variants {
		if v.TransformedCode == code {
			return true
		}
	}
	return false
}

// ValidateOrbit checks if an orbit has sufficient diversity
func (g *OrbitGenerator) ValidateOrbit(orbit *SemanticOrbit) error {
	if len(orbit.Variants) < g.config.MinSize {
		return fmt.Errorf("insufficient variants: got %d, need %d", len(orbit.Variants), g.config.MinSize)
	}

	// Check that we have at least 2 different transformation types
	types := make(map[TransformationType]bool)
	for _, v := range orbit.Variants {
		types[v.TransformType] = true
	}
	if len(types) < 2 {
		return fmt.Errorf("insufficient transformation diversity: only %d type(s)", len(types))
	}

	return nil
}
