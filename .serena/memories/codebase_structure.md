# Hooksy - Codebase Structure

```
hooksy/
├── cmd/
│   └── hooksy/
│       └── main.go              # CLI entry point
├── internal/
│   ├── cli/
│   │   ├── root.go              # Root command (cobra)
│   │   ├── inspect.go           # inspect command (main function)
│   │   ├── init.go              # init command
│   │   ├── validate.go          # validate command
│   │   ├── rules.go             # rules command group
│   │   └── generate.go          # generate-hooks command
│   ├── config/
│   │   ├── config.go            # Configuration types
│   │   └── loader.go            # Config file loading & merging
│   ├── engine/
│   │   ├── engine.go            # Main inspection engine
│   │   ├── matcher.go           # Regex pattern matching
│   │   └── evaluator.go         # Rule evaluation logic
│   ├── hooks/
│   │   └── types.go             # Hook input/output types
│   └── logger/
│       └── logger.go            # Structured logging (zerolog)
├── configs/
│   ├── default.yaml             # Default security rules
│   ├── strict.yaml              # Strict security profile
│   └── permissive.yaml          # Permissive profile
├── go.mod
├── go.sum
├── Makefile
├── README.md
└── PLAN.md                      # Development plan/roadmap
```

## Key Components

### cmd/hooksy/main.go
Minimal entry point that calls `cli.Execute()`.

### internal/cli/
CLI commands using Cobra. Each file corresponds to a command:
- `root.go` - Root command with global flags (-v, -c, -p)
- `inspect.go` - Main command called by Claude Code hooks
- `init.go` - Initialize config files
- `validate.go` - Validate config files
- `rules.go` - Rules subcommand (list, test)
- `generate.go` - Generate Claude Code hook config

### internal/engine/
Core inspection logic:
- `engine.go` - Main Engine struct with Inspect() method
- `evaluator.go` - Rule evaluation against hook inputs
- `matcher.go` - Regex pattern matching

### internal/config/
Configuration handling:
- `config.go` - Config, Settings, Rules, Rule structs
- `loader.go` - YAML loading and merging logic

### internal/hooks/
Hook types for Claude Code integration:
- `types.go` - Input/output types for all hook events

### internal/logger/
Structured logging using zerolog.
