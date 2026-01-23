// Package providers contains LLM provider implementations.
package providers

import (
	"github.com/ihavespoons/hooksy/internal/llm"
)

// Registry provides factory functions for all provider types.
type Registry struct {
	factories map[llm.ProviderType]llm.ProviderFactory
}

// NewRegistry creates a new provider registry with all providers registered.
func NewRegistry() *Registry {
	r := &Registry{
		factories: make(map[llm.ProviderType]llm.ProviderFactory),
	}

	// Register all providers
	r.Register(llm.ProviderClaudeCLI, NewClaudeCLIProvider)
	r.Register(llm.ProviderAnthropic, NewAnthropicProvider)
	r.Register(llm.ProviderOpenAI, NewOpenAIProvider)
	r.Register(llm.ProviderHuggingFace, NewHuggingFaceProvider)

	return r
}

// Register adds a provider factory to the registry.
func (r *Registry) Register(pt llm.ProviderType, factory llm.ProviderFactory) {
	r.factories[pt] = factory
}

// Get returns the factory for a provider type.
func (r *Registry) Get(pt llm.ProviderType) (llm.ProviderFactory, bool) {
	f, ok := r.factories[pt]
	return f, ok
}

// Factories returns all registered factories.
func (r *Registry) Factories() map[llm.ProviderType]llm.ProviderFactory {
	return r.factories
}

// DefaultFactories returns the default set of provider factories.
func DefaultFactories() map[llm.ProviderType]llm.ProviderFactory {
	return NewRegistry().Factories()
}
