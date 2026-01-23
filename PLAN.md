# Hooksy - Claude Code Security Inspector

## Overview

Hooksy is a Go CLI tool designed to act as a security gateway for Claude Code hooks. It receives hook events from Claude Code, inspects them against configurable security rules, and returns structured decisions (allow/deny/block) with detailed reasoning.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   Claude Code   │────▶│     Hooksy      │────▶│  Decision JSON  │
│   (Hook Event)  │     │  (Inspection)   │     │  (stdout)       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
            ┌───────────────┐     ┌───────────────┐
            │ Global Config │     │ Project Config│
            │ ~/.hooksy/    │     │ .hooksy/      │
            └───────────────┘     └───────────────┘
```

## Hook Integration Model

Hooksy will be invoked by Claude Code hooks like this:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "hooksy inspect --event PreToolUse"
          }
        ]
      }
    ],
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command", 
            "command": "hooksy inspect --event UserPromptSubmit"
          }
        ]
      }
    ]
  }
}
```

## CLI Commands

### Primary Command: `hooksy inspect`

```bash
# Receives JSON from stdin (Claude Code hook input)
# Outputs decision JSON to stdout
hooksy inspect --event <EventType>

# Options:
#   --event       Hook event type (PreToolUse, PostToolUse, UserPromptSubmit, etc.)
#   --config      Override config file path
#   --project     Override project directory
#   --verbose     Enable verbose logging to stderr
#   --dry-run     Show what would happen without blocking
```

### Utility Commands

```bash
# Initialize config in current project
hooksy init [--global]

# Validate configuration files
hooksy validate [--config <path>]

# List all active rules
hooksy rules list

# Test a rule against sample input
hooksy rules test --rule <name> --input <json-file>

# Show Claude Code hook configuration to add
hooksy generate-hooks [--events PreToolUse,PostToolUse,...]
```

## Configuration Schema

### File Locations (Merged in Order)

1. `~/.hooksy/config.yaml` - Global defaults
2. `.hooksy/config.yaml` - Project-specific overrides

### Configuration Structure

```yaml
# ~/.hooksy/config.yaml or .hooksy/config.yaml
version: "1"

# Global settings
settings:
  log_level: "info"          # debug, info, warn, error
  log_file: ""               # Optional file path for logging
  default_decision: "allow"  # allow, deny, ask
  
# Rules organized by hook event type
rules:
  # PreToolUse rules - inspect tool calls before execution
  PreToolUse:
    - name: "block-dangerous-commands"
      description: "Block potentially dangerous shell commands"
      enabled: true
      priority: 100  # Higher priority runs first
      conditions:
        tool_name: "^(Bash|mcp__.*__Bash)$"
        tool_input:
          command:
            - pattern: "rm\\s+-rf\\s+/"
              message: "Recursive deletion from root is blocked"
            - pattern: ":(){ :|:& };:"
              message: "Fork bombs are not allowed"
            - pattern: "curl.*\\|.*sh"
              message: "Piping curl to shell is blocked"
            - pattern: "wget.*\\|.*sh"
              message: "Piping wget to shell is blocked"
      decision: "deny"
      
    - name: "block-sensitive-file-access"
      description: "Prevent access to sensitive files"
      enabled: true
      priority: 90
      conditions:
        tool_name: "^(Read|Write|Edit|mcp__.*__(Read|Write|Edit))$"
        tool_input:
          file_path:
            - pattern: "\\.(env|pem|key|crt|p12|pfx)$"
              message: "Access to secrets/certificates blocked"
            - pattern: "/(ssh|gnupg|aws|kube)/.*"
              message: "Access to credential directories blocked"
            - pattern: "id_rsa|id_ed25519|id_ecdsa"
              message: "Access to SSH keys blocked"
      decision: "deny"

    - name: "require-dry-run-for-git-push"
      description: "Force dry-run on git push commands"
      enabled: true
      priority: 80
      conditions:
        tool_name: "Bash"
        tool_input:
          command:
            - pattern: "git\\s+push"
      action: "modify"
      modifications:
        tool_input:
          command:
            append: " --dry-run"
      decision: "allow"

  # PostToolUse rules - inspect results after execution
  PostToolUse:
    - name: "detect-secret-leakage"
      description: "Detect if secrets appear in command output"
      enabled: true
      priority: 100
      conditions:
        tool_response:
          - pattern: "AKIA[0-9A-Z]{16}"
            message: "AWS access key detected in output"
          - pattern: "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            message: "Private key detected in output"
          - pattern: "ghp_[a-zA-Z0-9]{36}"
            message: "GitHub token detected in output"
      decision: "block"
      system_message: "Sensitive data was detected in the output. The response has been blocked."

  # UserPromptSubmit rules - inspect user prompts
  UserPromptSubmit:
    - name: "detect-injection-attempts"
      description: "Detect prompt injection attempts"
      enabled: true
      priority: 100
      conditions:
        prompt:
          - pattern: "ignore (all |previous |prior )?instructions"
            message: "Potential prompt injection detected"
          - pattern: "you are now|pretend (to be|you are)"
            message: "Role manipulation attempt detected"
      decision: "ask"
      
  # Stop rules - control when agent should stop
  Stop:
    - name: "require-completion-verification"
      description: "Ensure tasks are actually complete"
      enabled: false
      conditions:
        # Future: LLM inspection
      decision: "allow"

# Allowlist - patterns that bypass security checks
allowlist:
  - name: "trusted-project-files"
    description: "Allow access to project configuration"
    conditions:
      tool_input:
        file_path:
          - pattern: "^\\./|\\.hooksy/|package\\.json|go\\.mod"
            
  - name: "safe-read-operations"  
    description: "Allow read-only operations"
    conditions:
      tool_name: "^Read$"
      tool_input:
        file_path:
          - pattern: "\\.(go|ts|js|py|md|yaml|json)$"

# Future: LLM-based inspection (v2)
llm_inspection:
  enabled: false
  provider: "anthropic"
  model: "claude-3-haiku-20240307"
  events:
    - Stop
    - UserPromptSubmit
  prompt_template: |
    Analyze the following Claude Code action for security concerns:
    
    Event: {{.EventName}}
    Data: {{.EventData}}
    
    Respond with JSON: {"decision": "allow|deny", "reason": "..."}
```

## Project Structure

```
hooksy/
├── cmd/
│   └── hooksy/
│       └── main.go              # CLI entry point
├── internal/
│   ├── cli/
│   │   ├── root.go              # Root command
│   │   ├── inspect.go           # inspect command
│   │   ├── init.go              # init command
│   │   ├── validate.go          # validate command
│   │   ├── rules.go             # rules command group
│   │   └── generate.go          # generate-hooks command
│   ├── config/
│   │   ├── config.go            # Configuration types
│   │   ├── loader.go            # Config file loading & merging
│   │   └── defaults.go          # Default configuration
│   ├── engine/
│   │   ├── engine.go            # Main inspection engine
│   │   ├── matcher.go           # Regex pattern matching
│   │   ├── evaluator.go         # Rule evaluation logic
│   │   └── decision.go          # Decision types and output
│   ├── hooks/
│   │   ├── types.go             # Hook input/output types
│   │   ├── pretooluse.go        # PreToolUse handler
│   │   ├── posttooluse.go       # PostToolUse handler
│   │   ├── userprompt.go        # UserPromptSubmit handler
│   │   └── common.go            # Shared hook utilities
│   └── logger/
│       └── logger.go            # Structured logging
├── pkg/
│   └── hooksy/
│       └── client.go            # Public API for embedding
├── configs/
│   ├── default.yaml             # Shipped default rules
│   └── examples/
│       ├── strict.yaml          # Strict security profile
│       └── permissive.yaml      # Permissive profile
├── go.mod
├── go.sum
├── Makefile
└── README.md
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

### Modified Input (v2.0.10+)
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

### Phase 1: Core Static Inspection (MVP) - COMPLETE
- [x] CLI scaffold with Cobra
- [x] Configuration loading (YAML)
- [x] Regex-based pattern matching engine
- [x] PreToolUse and PostToolUse handlers
- [x] JSON output formatting
- [x] Basic logging (zerolog)

### Phase 2: Extended Event Support - COMPLETE
- [x] UserPromptSubmit handler
- [x] Stop/SubagentStop handlers
- [x] Input modification support (append, prepend, replace)
- [x] Rule priority and ordering
- [x] Allowlist processing

### Phase 3: Developer Experience - COMPLETE
- [x] `hooksy init` command
- [x] `hooksy validate` command
- [x] `hooksy generate-hooks` command
- [x] `hooksy rules test` command
- [x] Verbose mode and debugging

### Phase 4: LLM Integration - COMPLETE
- [x] Multi-provider support (Claude CLI, Anthropic API, OpenAI, HuggingFace)
- [x] Provider fallback chain with automatic failover
- [x] Analysis modes: sync, async, hybrid
- [x] Configurable analysis triggers by event type
- [x] Custom prompt templates with placeholders
- [x] Response caching with TTL
- [x] Rate limiting (requests/min with burst)
- [x] Budget controls (daily spend limits)
- [x] `hooksy llm status` command
- [x] `hooksy llm test` command
- [x] Contextual analysis for PreToolUse
- [x] Intent vs action analysis for PostToolUse
- [x] Stop event analysis
- [x] Transcript analysis prompts

### Phase 5: Execution Trace Analysis - COMPLETE
- [x] Session tracking with SQLite storage
- [x] Event tracing across sessions
- [x] `hooksy trace list` command
- [x] `hooksy trace show` command
- [x] `hooksy trace clear` command
- [x] `hooksy trace analyze` command for transcript analysis
- [x] Deception indicator detection
- [x] Monitoring awareness pattern detection
- [x] Obfuscation attempt detection
- [x] Intent vs action mismatch detection
- [x] Risk scoring with severity levels
- [x] Sequence rules for multi-event pattern correlation
- [x] Configurable time windows for sequence analysis
- [x] Pattern labeling and event chaining

## Next Steps

1. ~~**Onboard with Serena** - Integrate with Serena MCP server for project management~~ DONE
2. ~~**Input modification** - Fully implement tool input modification (e.g., auto-add --dry-run)~~ DONE
3. ~~**Testing** - Add unit tests for engine, matcher, evaluator~~ DONE (99 tests, 91-100% coverage)
4. ~~**LLM integration** - Add multi-provider LLM support with fallback chain~~ DONE
5. ~~**Execution trace analysis** - Session tracking and behavioral analysis~~ DONE
6. **Rule inheritance** - Support rule composition and inheritance
7. **Metrics and audit logging** - Track decisions and generate reports
8. **Web dashboard** - Rule management and monitoring UI

## Dependencies

- `github.com/spf13/cobra` - CLI framework
- `github.com/spf13/viper` - Configuration management
- `gopkg.in/yaml.v3` - YAML parsing
- `github.com/rs/zerolog` - Structured logging
- `github.com/stretchr/testify` - Testing
- `github.com/mattn/go-sqlite3` - SQLite driver for trace storage
- `github.com/anthropics/anthropic-sdk-go` - Anthropic API client
- `github.com/sashabaranov/go-openai` - OpenAI API client

## Example Usage Flow

1. User configures Claude Code hooks to call hooksy
2. Claude Code attempts to run `rm -rf /tmp/important`
3. Claude Code invokes: `echo '<hook_input_json>' | hooksy inspect --event PreToolUse`
4. Hooksy:
   - Loads global config from `~/.hooksy/config.yaml`
   - Loads project config from `.hooksy/config.yaml`
   - Merges configs (project overrides global)
   - Parses hook input JSON
   - Evaluates rules in priority order
   - First match triggers decision
   - Outputs decision JSON to stdout
5. Claude Code receives deny decision and shows message to user

## Questions for Clarification (Resolved)

1. **Default behavior**: ~~Should the default be "allow" (permissive) or "deny" (restrictive) when no rules match?~~ RESOLVED: Configurable via `settings.default_decision`, defaults to "allow"
2. **Rule combination**: ~~Should multiple matching rules combine (all must pass) or first-match-wins?~~ RESOLVED: First-match-wins with priority ordering
3. **Logging location**: ~~Should logs go to stderr, a file, or both?~~ RESOLVED: Configurable via `settings.log_file`, defaults to stderr
4. **Installation method**: ~~Preferences for distribution (brew, go install, binary releases)?~~ RESOLVED: go install and binary releases via goreleaser
5. **MCP tool handling**: ~~Any specific MCP servers that need special handling?~~ RESOLVED: MCP tools matched via `mcp__.*__ToolName` patterns
