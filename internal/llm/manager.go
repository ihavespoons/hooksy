package llm

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ihavespoons/hooksy/internal/llm/cache"
	"github.com/ihavespoons/hooksy/internal/logger"
)

// Manager manages LLM providers, routing, caching, and rate limiting.
type Manager struct {
	cfg       *Config
	providers map[ProviderType]Provider
	cache     *cache.Cache
	rateLimiter *rateLimiter
	budget    *budgetTracker
	mu        sync.RWMutex
}

// ProviderFactory creates providers of a given type.
type ProviderFactory func(cfg *Config) (Provider, error)

// NewManager creates a new LLM manager.
func NewManager(cfg *Config, factories map[ProviderType]ProviderFactory) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid LLM config: %w", err)
	}

	m := &Manager{
		cfg:       cfg,
		providers: make(map[ProviderType]Provider),
	}

	// Initialize cache if enabled
	if cfg.Cache.Enabled {
		m.cache = cache.New(cfg.Cache.MaxEntries, cfg.Cache.TTL)
	}

	// Initialize rate limiter if enabled
	if cfg.RateLimit.Enabled {
		m.rateLimiter = newRateLimiter(cfg.RateLimit.RequestsPerMin, cfg.RateLimit.BurstSize)
	}

	// Initialize budget tracker if enabled
	if cfg.Budget.Enabled {
		m.budget = newBudgetTracker(cfg.Budget.DailyLimitCents, cfg.Budget.WarnAtPercent)
	}

	// Initialize providers
	if factories != nil {
		for _, pt := range cfg.ProviderOrder {
			factory, ok := factories[pt]
			if !ok {
				continue
			}

			provider, err := factory(cfg)
			if err != nil {
				logger.Warn().
					Str("provider", string(pt)).
					Err(err).
					Msg("Failed to create provider, skipping")
				continue
			}

			m.providers[pt] = provider
		}
	}

	return m, nil
}

// Analyze performs analysis using the provider fallback chain.
func (m *Manager) Analyze(ctx context.Context, req *AnalysisRequest) (*AnalysisResponse, error) {
	if !m.cfg.Enabled {
		return nil, ErrDisabled
	}

	// Check cache first
	if m.cache != nil {
		cacheKey := m.cacheKey(req)
		if cached, ok := m.cache.Get(cacheKey); ok {
			resp := cached.(*AnalysisResponse)
			resp.Cached = true
			logger.Debug().
				Str("cache_key", cacheKey[:8]).
				Msg("Cache hit for LLM analysis")
			return resp, nil
		}
	}

	// Check rate limit
	if m.rateLimiter != nil && !m.rateLimiter.Allow() {
		return nil, ErrRateLimited
	}

	// Check budget
	if m.budget != nil {
		if m.budget.Exceeded() {
			return nil, ErrBudgetExceeded
		}
	}

	// Try providers in order
	var lastErr error
	for _, pt := range m.cfg.ProviderOrder {
		provider, ok := m.providers[pt]
		if !ok {
			continue
		}

		// Check if provider is available
		if !provider.Available(ctx) {
			logger.Debug().
				Str("provider", string(pt)).
				Msg("Provider not available, trying next")
			continue
		}

		// Check if we can afford this provider
		if m.budget != nil {
			cost := provider.EstimateCost(req)
			if !m.budget.CanAfford(cost) {
				logger.Debug().
					Str("provider", string(pt)).
					Float64("cost", cost).
					Msg("Cannot afford provider, trying next")
				continue
			}
		}

		// Get timeout for this provider type
		timeout := m.getTimeout(pt)
		ctx, cancel := context.WithTimeout(ctx, timeout)

		// Perform analysis
		start := time.Now()
		resp, err := provider.Analyze(ctx, req)
		cancel()

		if err != nil {
			lastErr = err
			logger.Warn().
				Str("provider", string(pt)).
				Err(err).
				Msg("Provider analysis failed, trying next")
			continue
		}

		// Record cost
		if m.budget != nil && resp.CostCents > 0 {
			m.budget.Record(resp.CostCents)
		}

		// Update latency
		resp.Latency = time.Since(start)

		// Cache response
		if m.cache != nil {
			cacheKey := m.cacheKey(req)
			m.cache.Set(cacheKey, resp)
		}

		logger.Debug().
			Str("provider", string(pt)).
			Str("decision", string(resp.Decision)).
			Float32("confidence", resp.Confidence).
			Dur("latency", resp.Latency).
			Msg("LLM analysis complete")

		return resp, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed: %w", lastErr)
	}
	return nil, ErrNoProviders
}

// AvailableProviders returns a list of currently available providers.
func (m *Manager) AvailableProviders(ctx context.Context) []ProviderType {
	var available []ProviderType
	for pt, provider := range m.providers {
		if provider.Available(ctx) {
			available = append(available, pt)
		}
	}
	return available
}

// ProviderStatus returns the status of all configured providers.
func (m *Manager) ProviderStatus(ctx context.Context) map[ProviderType]ProviderStatusInfo {
	status := make(map[ProviderType]ProviderStatusInfo)
	for _, pt := range m.cfg.ProviderOrder {
		provider, ok := m.providers[pt]
		if !ok {
			status[pt] = ProviderStatusInfo{
				Available: false,
				Reason:    "not configured",
			}
			continue
		}
		available := provider.Available(ctx)
		info := ProviderStatusInfo{
			Available: available,
			Name:      provider.Name(),
		}
		if !available {
			info.Reason = "provider check failed"
		}
		status[pt] = info
	}
	return status
}

// ProviderStatusInfo contains status information for a provider.
type ProviderStatusInfo struct {
	Available bool
	Name      string
	Reason    string
}

// CacheStats returns cache statistics.
func (m *Manager) CacheStats() *cache.Stats {
	if m.cache == nil {
		return nil
	}
	stats := m.cache.Stats()
	return &stats
}

// BudgetStatus returns budget status.
func (m *Manager) BudgetStatus() *BudgetStatus {
	if m.budget == nil {
		return nil
	}
	return m.budget.Status()
}

// Close releases all resources.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errs []error
	for _, provider := range m.providers {
		if err := provider.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors closing providers: %v", errs)
	}
	return nil
}

// getTimeout returns the appropriate timeout for a provider type.
func (m *Manager) getTimeout(pt ProviderType) time.Duration {
	switch pt {
	case ProviderClaudeCLI:
		return m.cfg.Timeouts.CLI
	default:
		return m.cfg.Timeouts.API
	}
}

// cacheKey generates a cache key for a request.
func (m *Manager) cacheKey(req *AnalysisRequest) string {
	return cache.HashKey(
		req.Type,
		req.EventType,
		req.ToolName,
		req.ToolInput,
		req.ToolResponse,
		req.Prompt,
	)
}

// Errors returned by the manager.
var (
	ErrDisabled       = errors.New("llm analysis is disabled")
	ErrNoProviders    = errors.New("no providers available")
	ErrRateLimited    = errors.New("rate limit exceeded")
	ErrBudgetExceeded = errors.New("daily budget exceeded")
)

// rateLimiter implements a token bucket rate limiter.
type rateLimiter struct {
	rate      float64 // tokens per second
	burst     int
	tokens    float64
	lastTime  time.Time
	mu        sync.Mutex
}

func newRateLimiter(requestsPerMin, burstSize int) *rateLimiter {
	rate := float64(requestsPerMin) / 60.0
	return &rateLimiter{
		rate:     rate,
		burst:    burstSize,
		tokens:   float64(burstSize),
		lastTime: time.Now(),
	}
}

func (r *rateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(r.lastTime).Seconds()
	r.lastTime = now

	// Add tokens based on elapsed time
	r.tokens += elapsed * r.rate
	if r.tokens > float64(r.burst) {
		r.tokens = float64(r.burst)
	}

	// Check if we have a token
	if r.tokens >= 1 {
		r.tokens--
		return true
	}
	return false
}

// budgetTracker tracks daily API spending.
type budgetTracker struct {
	dailyLimitCents int
	warnPercent     int
	spentCents      int64 // atomic
	dayStart        time.Time
	mu              sync.Mutex
}

func newBudgetTracker(dailyLimitCents, warnPercent int) *budgetTracker {
	return &budgetTracker{
		dailyLimitCents: dailyLimitCents,
		warnPercent:     warnPercent,
		dayStart:        startOfDay(time.Now()),
	}
}

func (b *budgetTracker) Record(costCents float64) {
	b.maybeResetDay()
	atomic.AddInt64(&b.spentCents, int64(costCents*100)) // Store as hundredths of cents for precision
}

func (b *budgetTracker) CanAfford(costCents float64) bool {
	b.maybeResetDay()
	spent := float64(atomic.LoadInt64(&b.spentCents)) / 100.0
	return spent+costCents <= float64(b.dailyLimitCents)
}

func (b *budgetTracker) Exceeded() bool {
	b.maybeResetDay()
	spent := float64(atomic.LoadInt64(&b.spentCents)) / 100.0
	return spent >= float64(b.dailyLimitCents)
}

func (b *budgetTracker) Status() *BudgetStatus {
	b.maybeResetDay()
	spent := float64(atomic.LoadInt64(&b.spentCents)) / 100.0
	return &BudgetStatus{
		SpentCents:      spent,
		LimitCents:      b.dailyLimitCents,
		RemainingCents:  float64(b.dailyLimitCents) - spent,
		PercentUsed:     (spent / float64(b.dailyLimitCents)) * 100,
		WarnThreshold:   b.warnPercent,
		Exceeded:        spent >= float64(b.dailyLimitCents),
		Warning:         spent >= float64(b.dailyLimitCents*b.warnPercent)/100,
	}
}

func (b *budgetTracker) maybeResetDay() {
	b.mu.Lock()
	defer b.mu.Unlock()

	today := startOfDay(time.Now())
	if today.After(b.dayStart) {
		b.dayStart = today
		atomic.StoreInt64(&b.spentCents, 0)
	}
}

func startOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}

// BudgetStatus contains budget tracking information.
type BudgetStatus struct {
	SpentCents     float64
	LimitCents     int
	RemainingCents float64
	PercentUsed    float64
	WarnThreshold  int
	Exceeded       bool
	Warning        bool
}
