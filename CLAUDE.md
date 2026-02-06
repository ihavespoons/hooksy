# Hooksy Development Guide

## Build & Test

```bash
make build          # Build binary
make test           # Run unit tests (go test -v ./...)
make test-integration  # Run shell-based integration smoke tests
```

### Running Tests

```bash
# Unit tests (fast, run frequently)
go test ./... -count=1

# Unit tests with coverage
go test ./... -count=1 -coverprofile=coverage.out
go tool cover -func=coverage.out

# Integration tests (builds binary, tests CLI end-to-end)
go test ./test/integration/... -count=1 -v

# Specific package tests
go test ./internal/config/... -count=1 -v
go test ./internal/trace/... -count=1 -v
go test ./internal/engine/... -count=1 -v
```

**Integration tests exist and must be run** when making changes to CLI commands, configuration loading, or hook output format. They live in `test/integration/` and test the full binary end-to-end with testdata fixtures.

## Architecture

- **CLI**: `internal/cli/` - Cobra commands (inspect, setup, validate, rules, trace, daemon)
- **Config**: `internal/config/` - YAML config types, loading, merging (global + project)
- **Engine**: `internal/engine/` - Rule evaluation engine, connects config to trace analysis
- **Trace**: `internal/trace/` - SQLite session store, sequence analysis, transcript analysis
- **Hooks**: `internal/hooks/` - Claude Code hook types and output constructors
- **LLM**: `internal/llm/` - LLM provider integrations
- **Dashboard**: `internal/dashboard/` - Web dashboard and daemon

## Key Patterns

- Config merging: global (`~/.hooksy/config.yaml`) + project (`.hooksy/config.yaml`). Bool fields use group-level zero-value detection for merge.
- Embedded configs: `internal/cli/configs/*.yaml` via `//go:embed` for `hooksy setup` profiles
- SQLite via `modernc.org/sqlite` (pure Go, no CGO)
- No testify; tests use stdlib `testing` only

## Lint

When resolving linter issues, fix the underlying code. Do not add exclusions or configure the linter to ignore issues.
