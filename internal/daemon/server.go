package daemon

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/ihavespoons/hooksy/internal/config"
	"github.com/ihavespoons/hooksy/internal/logger"
	"github.com/ihavespoons/hooksy/internal/trace"
)

// Server represents the dashboard HTTP server
type Server struct {
	httpServer  *http.Server
	handlers    *Handlers
	broadcaster *SSEBroadcaster
	lifecycle   *Lifecycle
	port        int
}

// NewServer creates a new dashboard server
func NewServer(cfg *config.Config, store trace.SessionStore, version string) *Server {
	handlers := NewHandlers(store, cfg, version)
	broadcaster := NewSSEBroadcaster(store)
	lifecycle := NewLifecycle(cfg.Settings.Daemon)

	port := cfg.Settings.Daemon.Port
	if port == 0 {
		port = 8741
	}

	mux := http.NewServeMux()

	// Static files
	mux.HandleFunc("GET /", serveIndex)
	mux.HandleFunc("GET /static/app.js", serveAppJS)
	mux.HandleFunc("GET /static/styles.css", serveStylesCSS)

	// API endpoints
	mux.HandleFunc("GET /health", handlers.Health)
	mux.HandleFunc("GET /api/sessions", handlers.Sessions)
	mux.HandleFunc("GET /api/events", handlers.Events)
	mux.HandleFunc("GET /api/events/export", handlers.ExportEvents)
	mux.HandleFunc("GET /api/events/", handlers.EventDetail)
	mux.HandleFunc("GET /api/rules", handlers.Rules)
	mux.HandleFunc("GET /api/stats", handlers.Stats)

	// SSE endpoint
	mux.HandleFunc("GET /sse/events", broadcaster.ServeHTTP)

	return &Server{
		httpServer: &http.Server{
			Addr:              fmt.Sprintf("127.0.0.1:%d", port),
			Handler:           corsMiddleware(mux),
			ReadHeaderTimeout: 10 * time.Second,
		},
		handlers:    handlers,
		broadcaster: broadcaster,
		lifecycle:   lifecycle,
		port:        port,
	}
}

// Start starts the server
func (s *Server) Start(ctx context.Context) error {
	// Write PID file
	if err := s.lifecycle.WritePID(); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}

	// Start SSE broadcaster
	s.broadcaster.Start(ctx)

	logger.Info().
		Int("port", s.port).
		Str("url", fmt.Sprintf("http://127.0.0.1:%d", s.port)).
		Msg("Starting hooksy dashboard daemon")

	// Start server
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error().Err(err).Msg("Server error")
		}
	}()

	return nil
}

// Stop gracefully stops the server
func (s *Server) Stop(ctx context.Context) error {
	logger.Info().Msg("Stopping hooksy dashboard daemon")

	// Stop SSE broadcaster
	s.broadcaster.Stop()

	// Remove PID file
	_ = s.lifecycle.RemovePID()

	// Shutdown HTTP server
	return s.httpServer.Shutdown(ctx)
}

// Port returns the server port
func (s *Server) Port() int {
	return s.port
}

// Lifecycle returns the lifecycle manager
func (s *Server) Lifecycle() *Lifecycle {
	return s.lifecycle
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func serveAppJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(appJS)
}

func serveStylesCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(stylesCSS)
}
