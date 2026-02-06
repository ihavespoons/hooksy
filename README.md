# Hooksy

A security inspection tool for Claude Code hooks. Hooksy intercepts Claude Code hook events, evaluates them against configurable security rules using regex patterns, and returns structured decisions (allow/deny/block). It includes LLM-based analysis for semantic understanding, execution trace analysis for detecting suspicious behavioral patterns, and a real-time web dashboard.

## Installation

### Homebrew (macOS/Linux)

```bash
brew install ihavespoons/tap/hooksy
```

### Go Install

```bash
go install github.com/ihavespoons/hooksy/cmd/hooksy@latest
```

### Download Binary

Download pre-built binaries from the [releases page](https://github.com/ihavespoons/hooksy/releases).

### Build from Source

```bash
git clone https://github.com/ihavespoons/hooksy.git
cd hooksy
make build
```

## Quick Start

1. Initialize configuration:

```bash
hooksy init
```

2. Generate Claude Code hook configuration:

```bash
hooksy generate-hooks
```

3. Add the generated hooks to your Claude Code settings (`~/.claude/settings.json` or `.claude/settings.json`).

## Usage

### Commands

```bash
# Inspect a hook event (called by Claude Code)
hooksy inspect --event PreToolUse

# Initialize configuration
hooksy init           # Project-level (.hooksy/config.yaml)
hooksy init --global  # Global (~/.hooksy/config.yaml)

# Validate configuration
hooksy validate

# List active rules
hooksy rules list

# Test a rule against sample input
hooksy rules test --event PreToolUse --input sample.json

# Generate Claude Code hooks configuration
hooksy generate-hooks --events PreToolUse,PostToolUse,UserPromptSubmit

# LLM provider management
hooksy llm status                           # Show LLM provider availability
hooksy llm test "Is this safe: rm -rf /"    # Test a prompt with configured providers
hooksy llm test --provider anthropic "..."  # Test with a specific provider

# Execution trace management
hooksy trace list                           # List traced sessions
hooksy trace show <session-id>              # Show events for a session
hooksy trace clear --all                    # Clear all trace data
hooksy trace analyze <transcript.jsonl>     # Analyze a transcript for suspicious patterns

# Dashboard daemon
hooksy daemon start              # Start in foreground
hooksy daemon start --background # Start in background
hooksy daemon stop               # Stop the running daemon
hooksy daemon status             # Check if the daemon is running

# Version information
hooksy version
```

### Flags

- `-v, --verbose` - Enable verbose logging to stderr
- `-c, --config` - Override config file path
- `-p, --project` - Override project directory
- `--dry-run` - Show what would happen without blocking (inspect command)

## Configuration

Hooksy looks for configuration in two locations (merged in order):

1. `~/.hooksy/config.yaml` - Global defaults
2. `.hooksy/config.yaml` - Project-specific overrides

### Example Configuration

```yaml
version: "1"

settings:
  log_level: info
  default_decision: allow  # allow, deny, or ask

  trace:
    enabled: true
    storage_path: ""  # Default: ~/.hooksy/traces/sessions.db
    session_ttl: 24h
    max_events_per_session: 1000
    cleanup_probability: 0.1

    transcript_analysis:
      enabled: true
      risk_threshold: 0.3  # Minimum risk score to trigger action (0.0-1.0)

  daemon:
    enabled: false
    port: 8741
    auto_start: false

rules:
  PreToolUse:
    - name: block-dangerous-commands
      description: Block potentially dangerous shell commands
      enabled: true
      priority: 100
      conditions:
        tool_name: "^(Bash|mcp__.*__Bash)$"
        tool_input:
          command:
            - pattern: 'rm\s+-rf\s+/'
              message: Recursive deletion from root is blocked
            - pattern: 'curl.*\|.*sh'
              message: Piping curl to shell is blocked
      decision: deny

  PostToolUse:
    - name: detect-secret-leakage
      description: Detect if secrets appear in command output
      enabled: true
      priority: 100
      conditions:
        tool_response:
          - pattern: 'AKIA[0-9A-Z]{16}'
            message: AWS access key detected in output
          - pattern: '-----BEGIN.*PRIVATE KEY-----'
            message: Private key detected in output
      decision: block
      system_message: Sensitive data detected. Output blocked.

  UserPromptSubmit:
    - name: detect-injection-attempts
      description: Detect prompt injection attempts
      enabled: false
      conditions:
        prompt:
          - pattern: '(?i)ignore.*instructions'
            message: Potential prompt injection
      decision: ask

allowlist:
  - name: allow-project-configs
    description: Allow access to project config files
    enabled: true
    conditions:
      tool_input:
        file_path:
          - pattern: 'package\.json$'
          - pattern: 'go\.(mod|sum)$'
    decision: allow
```

## Security Profiles

Pre-configured security profiles are included:

- **default.yaml** - Balanced security for most use cases
- **strict.yaml** - Maximum security, denies by default
- **permissive.yaml** - Minimal friction, blocks only catastrophic operations
- **llm-example.yaml** - Example LLM-enhanced configuration
- **trace-analysis.yaml** - Execution trace and sequence rule example

Use them with:

```bash
hooksy inspect --event PreToolUse --config configs/strict.yaml
```

## LLM Analysis

Hooksy supports LLM-based analysis to augment rule-based inspection with semantic understanding. This enables detection of subtle threats that pattern matching alone cannot catch.

### Supported Providers

| Provider | Type | Cost | Notes |
|----------|------|------|-------|
| `claude_cli` | CLI | Free* | Uses Claude Code CLI (requires Pro subscription) |
| `anthropic` | API | Paid | Direct Anthropic API access |
| `openai` | API | Paid | OpenAI API (GPT-4 Turbo) |
| `huggingface` | API | Paid | HuggingFace Inference API |

Providers are tried in configured order until one succeeds (fallback chain).

### Analysis Types

- **Contextual Analysis** - Evaluates if a tool use is appropriate for the context
- **Intent vs Action** - Compares stated intent with actual tool behavior
- **Transcript Analysis** - Analyzes full session transcripts for deception patterns
- **Stop Analysis** - Evaluates suspicious session terminations

### Analysis Modes

- **sync** - Block until analysis completes (thorough but adds latency)
- **async** - Fire-and-forget, log results (no latency impact)
- **hybrid** - Sync for pre-events, async for post/stop events (recommended)

### Configuration Example

```yaml
llm:
  enabled: true
  mode: hybrid
  provider_order:
    - claude_cli
    - anthropic
    - openai

  providers:
    claude_cli:
      enabled: true
      max_tokens: 1024
    anthropic:
      enabled: true
      model: claude-sonnet-4-20250514

  analysis:
    event_types: [PreToolUse, PostToolUse, Stop]
    min_confidence: 0.7
    triggers:
      - event_type: PreToolUse
        conditions:
          tool_names: ["^Bash$"]
          no_rule_match: true
        analysis_types: [contextual]
        mode: sync

  cache:
    enabled: true
    max_entries: 1000
    ttl: 5m

  budget:
    enabled: true
    daily_limit_cents: 500
    warn_at_percent: 80
```

## Execution Trace Analysis

Hooksy can track and analyze execution traces across sessions to detect suspicious multi-event patterns.

### Transcript Analysis

Analyze Claude Code transcript files for behavioral patterns:

```bash
hooksy trace analyze ~/.claude/projects/myproject/transcript.jsonl
hooksy trace analyze transcript.jsonl --verbose --json
```

Detects:
- **Deception Indicators** - Attempts to hide actions or misdirect
- **Monitoring Awareness** - Checking if being watched, trying to evade detection
- **Obfuscation Attempts** - Encoding commands, evasion techniques
- **Intent-Action Mismatches** - Saying one thing but doing another

The transcript analyzer can be configured independently from trace storage:

```yaml
settings:
  trace:
    enabled: true
    transcript_analysis:
      enabled: true        # Enable/disable transcript pattern analysis
      risk_threshold: 0.3  # Minimum risk score to trigger action (0.0-1.0)
```

The `risk_threshold` controls when the analyzer takes action:
- **Below threshold** - Allowed, no action taken
- **Threshold to threshold+0.3** - Ask (prompt user for approval)
- **Above threshold+0.3** (capped at 0.9) - Deny

### Sequence Rules

Sequence rules detect suspicious patterns across multiple events within a time window:

```yaml
sequence_rules:
  # Detect credential access followed by network activity
  - name: credential-then-network
    description: Reading credentials followed by network requests
    enabled: true
    severity: critical
    window: 5m
    events:
      - event_type: PostToolUse
        tool_name: "^(Read|Bash)$"
        tool_input:
          file_path: "\\.(env|pem|key)$"
        label: credential_read

      - event_type: PreToolUse
        tool_name: "^Bash$"
        tool_input:
          command: "(curl|wget|nc).*"
        after: credential_read

    decision: deny
    message: "Network request detected after reading credentials"
```

### Session Tracing

Enable session tracing to record events for analysis:

```yaml
settings:
  trace:
    enabled: true
    storage_path: ""  # Default: ~/.hooksy/traces/sessions.db
    session_ttl: 24h
    max_events_per_session: 1000
    cleanup_probability: 0.1
```

## Dashboard

Hooksy includes a real-time web dashboard for monitoring hook events, viewing session activity, and tracking rule violations.

### Configuration

```yaml
settings:
  daemon:
    enabled: true
    port: 8741       # Dashboard port
    auto_start: false # Auto-start on first inspect
```

### Usage

```bash
hooksy daemon start              # Start in foreground
hooksy daemon start --background # Run as background process
hooksy daemon stop               # Stop the daemon
hooksy daemon status             # Check status
```

The dashboard is accessible at `http://127.0.0.1:8741` (or your configured port).

## Hook Events

Hooksy supports all Claude Code hook events:

| Event | Description | Rule Support |
|-------|-------------|--------------|
| `PreToolUse` | Before tool execution | Yes |
| `PostToolUse` | After tool completion | Yes |
| `UserPromptSubmit` | User prompt submission | Yes |
| `Stop` | Main agent stopping | LLM analysis only |
| `SubagentStop` | Subagent stopping | Pass-through |
| `Notification` | System notifications | Pass-through |
| `SessionStart` | Session initialization | Trace initialization |
| `SessionEnd` | Session termination | Trace cleanup |
| `PermissionRequest` | Permission dialogs | Pass-through |
| `PreCompact` | Before compacting | Pass-through |

## Decisions

Rules can return these decisions:

- **allow** - Permit the action
- **deny** - Reject the action (Claude retries with feedback)
- **ask** - Prompt the user for approval
- **block** - Stop processing entirely with a message

## Claude Code Integration

Add to your Claude Code settings:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "hooksy inspect --event PreToolUse",
            "timeout": 30
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "hooksy inspect --event PostToolUse",
            "timeout": 30
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "hooksy inspect --event UserPromptSubmit",
            "timeout": 30
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "hooksy inspect --event SessionStart",
            "timeout": 30
          }
        ]
      }
    ],
    "SessionEnd": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "hooksy inspect --event SessionEnd",
            "timeout": 30
          }
        ]
      }
    ]
  }
}
```

Or generate this automatically with `hooksy generate-hooks`.

## Development

```bash
# Build
make build

# Run tests
make test

# Run integration tests
make test-integration

# Validate all configs
make validate

# Build for all platforms
make release
```

## Roadmap

### Completed

- [x] LLM-based inspection with multiple provider support (Claude CLI, Anthropic, OpenAI, HuggingFace)
- [x] Input modification support (e.g., auto-add --dry-run flags)
- [x] Execution trace analysis for multi-event pattern detection
- [x] Transcript analysis for deception and behavioral pattern detection
- [x] Sequence rules for cross-event correlation
- [x] LLM response caching, rate limiting, and budget controls
- [x] Real-time web dashboard with session monitoring
- [x] Configurable transcript analysis with risk threshold

### Planned

- [ ] Rule inheritance and composition
- [ ] Metrics and audit logging
- [ ] Enhanced prompt templates with few-shot examples

## License

Apache 2.0
