# Hooksy - Project Overview

## Purpose
Hooksy is a Go CLI tool that acts as a security gateway for Claude Code hooks. It intercepts Claude Code hook events, evaluates them against configurable security rules using regex patterns, and returns structured decisions (allow/deny/block/ask).

## Key Features
- Receives hook events from Claude Code via stdin as JSON
- Inspects against configurable YAML security rules
- Returns structured JSON decisions to stdout
- Supports global (~/.hooksy/config.yaml) and project-level (.hooksy/config.yaml) configuration
- Multiple security profiles: default, strict, permissive

## Supported Hook Events
| Event | Description |
|-------|-------------|
| PreToolUse | Before tool execution |
| PostToolUse | After tool completion |
| UserPromptSubmit | User prompt submission |
| Stop | Main agent stopping |
| SubagentStop | Subagent stopping |
| PermissionRequest | Permission dialogs |
| Notification | System notifications |
| SessionStart | Session initialization |
| SessionEnd | Session termination |
| PreCompact | Before compacting |

## Decision Types
- **allow** - Permit the action
- **deny** - Reject the action (Claude retries with feedback)
- **ask** - Prompt the user for approval
- **block** - Stop processing entirely with a message

## Integration with Claude Code
Hooksy is invoked by Claude Code hooks configured in `~/.claude/settings.json` or `.claude/settings.json`.
