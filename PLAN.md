# Hooksy - Claude Code Security Inspector

## Overview

Hooksy is a Go CLI tool designed to act as a security gateway for Claude Code hooks. It receives hook events from Claude Code, inspects them against configurable security rules, and returns structured decisions (allow/deny/block) with detailed reasoning. It includes LLM-based semantic analysis, execution trace analysis for behavioral pattern detection, and a real-time web dashboard.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Claude Code   │────▶│     Hooksy      │────▶│  Decision JSON  │
│   (Hook Event)  │     │  (Inspection)   │     │  (stdout)       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                    ┌──────────┼──────────┐
                    ▼          ▼          ▼
            ┌───────────┐ ┌────────┐ ┌──────────┐
            │   Rules   │ │  LLM   │ │  Trace   │
            │  Engine   │ │Analysis│ │ Analysis │
            └───────────┘ └────────┘ └──────────┘
                    │          │          │
             ┌──────┴──────────┴──────────┴──────┐
             ▼                                   ▼
     ┌───────────────┐                   ┌───────────────┐
     │ Global Config │                   │ Project Config│
     │ ~/.hooksy/    │                   │ .hooksy/      │
     └───────────────┘                   └───────────────┘
```

## Project Structure

```
hooksy/
├── cmd/
│   └── hooksy/
│       └── main.go              # CLI entry point
├── internal/
│   ├── cli/
│   │   ├── root.go              # Root command and version
│   │   ├── inspect.go           # inspect command
│   │   ├── init.go              # init command
│   │   ├── validate.go          # validate command
│   │   ├── rules.go             # rules command group
│   │   ├── generate.go          # generate-hooks command
│   │   ├── llm.go               # llm status/test commands
│   │   ├── trace.go             # trace list/show/clear/analyze commands
│   │   └── daemon.go            # daemon start/stop/status commands
│   ├── config/
│   │   ├── config.go            # Configuration types and defaults
│   │   ├── config_test.go       # Config tests
│   │   ├── loader.go            # Config file loading & merging
│   │   └── loader_test.go       # Loader tests
│   ├── engine/
│   │   ├── engine.go            # Main inspection engine
│   │   ├── engine_test.go       # Engine tests
│   │   ├── evaluator.go         # Rule evaluation logic
│   │   ├── evaluator_test.go    # Evaluator tests
│   │   ├── matcher.go           # Regex pattern matching
│   │   └── matcher_test.go      # Matcher tests
│   ├── hooks/
│   │   ├── types.go             # Hook input/output types
│   │   └── types_test.go        # Hook type tests
│   ├── logger/
│   │   └── logger.go            # Structured logging (zerolog)
│   ├── trace/
│   │   ├── analyzer.go          # Cross-event pattern analyzer
│   │   ├── analyzer_test.go     # Analyzer tests
│   │   ├── intent.go            # Intent vs action checker
│   │   ├── store.go             # SQLite session store
│   │   ├── store_test.go        # Store tests
│   │   ├── transcript.go        # Transcript pattern analyzer
│   │   ├── transcript_test.go   # Transcript tests
│   │   └── types.go             # Trace data types
│   ├── llm/
│   │   ├── analyzer.go          # LLM-based analysis orchestrator
│   │   ├── config.go            # LLM configuration types
│   │   ├── config_test.go       # LLM config tests
│   │   ├── manager.go           # Provider manager with fallback
│   │   ├── manager_test.go      # Manager tests
│   │   ├── provider.go          # Provider interface
│   │   ├── cache/
│   │   │   ├── cache.go         # Response caching
│   │   │   └── cache_test.go    # Cache tests
│   │   ├── prompts/
│   │   │   ├── context.go       # Contextual analysis prompts
│   │   │   ├── intent.go        # Intent analysis prompts
│   │   │   ├── stop.go          # Stop analysis prompts
│   │   │   └── transcript.go    # Transcript analysis prompts
│   │   └── providers/
│   │       ├── registry.go      # Provider registry
│   │       ├── anthropic.go     # Anthropic API provider
│   │       ├── claude_cli.go    # Claude CLI provider
│   │       ├── openai.go        # OpenAI API provider
│   │       └── huggingface.go   # HuggingFace API provider
│   └── daemon/
│       ├── server.go            # HTTP server for dashboard
│       ├── handlers.go          # API endpoint handlers
│       ├── lifecycle.go         # Daemon lifecycle (PID, background)
│       ├── sse.go               # Server-sent events for real-time updates
│       ├── embed.go             # Static file embedding
│       ├── types.go             # Dashboard data types
│       └── static/
│           ├── index.html       # Dashboard HTML
│           ├── styles.css       # Dashboard styles
│           └── app.js           # Dashboard JavaScript
├── configs/
│   ├── default.yaml             # Balanced security profile
│   ├── strict.yaml              # Maximum security profile
│   ├── permissive.yaml          # Minimal friction profile
│   ├── llm-example.yaml         # LLM-enhanced configuration example
│   └── trace-analysis.yaml      # Trace analysis example
├── test/
│   └── integration/             # Integration test fixtures
├── go.mod
├── go.sum
├── Makefile
├── LICENSE
├── README.md
├── CHANGELOG.md
└── PLAN.md
```

## Output Format

Hooksy outputs JSON to stdout matching Claude Code's expected format:

### Allow Decision
```json
{
  "continue": true,
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "All security checks passed"
  }
}
```

### Deny Decision
```json
{
  "continue": true,
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Rule 'block-dangerous-commands' triggered: Recursive deletion from root is blocked"
  }
}
```

### Block Decision (Stop Processing)
```json
{
  "continue": false,
  "stopReason": "Security violation detected",
  "systemMessage": "The requested action was blocked by security policy: Access to SSH keys blocked"
}
```

### Modified Input
```json
{
  "continue": true,
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "Modified command to add --dry-run flag",
    "updatedInput": {
      "command": "git push origin main --dry-run"
    }
  }
}
```

## Implementation Status

All core phases are complete:

- [x] **Core Static Inspection** - CLI, config loading, regex matching, PreToolUse/PostToolUse/UserPromptSubmit handlers, JSON output, logging
- [x] **Extended Event Support** - All hook event types, input modification, rule priority, allowlist processing
- [x] **Developer Experience** - init, validate, generate-hooks, rules test, verbose mode
- [x] **LLM Integration** - Multi-provider support, fallback chain, sync/async/hybrid modes, caching, rate limiting, budget controls
- [x] **Execution Trace Analysis** - SQLite session storage, sequence rules, transcript analysis, risk scoring, intent mismatch detection
- [x] **Dashboard** - Real-time web dashboard with SSE, session monitoring, event viewing, daemon lifecycle management
- [x] **Configurable Transcript Analysis** - Enable/disable toggle, configurable risk threshold

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- `gopkg.in/yaml.v3` - YAML parsing
- `github.com/rs/zerolog` - Structured logging
- `modernc.org/sqlite` - Pure-Go SQLite driver for trace storage
