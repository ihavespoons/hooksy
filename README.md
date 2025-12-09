# Hooksy

A security inspection tool for Claude Code hooks. Hooksy intercepts Claude Code hook events, evaluates them against configurable security rules using regex patterns, and returns structured decisions (allow/deny/block).

## Installation

```bash
# From source
go install github.com/bengittins/hooksy/cmd/hooksy@latest

# Or build locally
git clone https://github.com/bengittins/hooksy.git
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

Three pre-configured security profiles are included:

- **default.yaml** - Balanced security for most use cases
- **strict.yaml** - Maximum security, denies by default
- **permissive.yaml** - Minimal friction, blocks only catastrophic operations

Use them with:

```bash
hooksy inspect --event PreToolUse --config configs/strict.yaml
```

## Hook Events

Hooksy supports all Claude Code hook events:

| Event | Description | Matcher Support |
|-------|-------------|-----------------|
| `PreToolUse` | Before tool execution | Yes |
| `PostToolUse` | After tool completion | Yes |
| `UserPromptSubmit` | User prompt submission | No |
| `Stop` | Main agent stopping | No |
| `SubagentStop` | Subagent stopping | No |
| `PermissionRequest` | Permission dialogs | Yes |
| `Notification` | System notifications | Yes |
| `SessionStart` | Session initialization | Yes |
| `SessionEnd` | Session termination | No |
| `PreCompact` | Before compacting | Yes |

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
    ]
  }
}
```

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

- [ ] LLM-based inspection using Claude Haiku for complex pattern detection
- [ ] Input modification support (e.g., auto-add --dry-run flags)
- [ ] Rule inheritance and composition
- [ ] Metrics and audit logging
- [ ] Web dashboard for rule management

## License

MIT
