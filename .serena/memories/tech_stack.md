# Hooksy - Tech Stack

## Language
- **Go 1.25.4**

## Dependencies

### Core
- `github.com/spf13/cobra` - CLI framework
- `gopkg.in/yaml.v3` - YAML parsing for configuration
- `github.com/rs/zerolog` - Structured logging

### Supporting
- `github.com/spf13/pflag` - Flag parsing (via Cobra)
- `github.com/mattn/go-colorable` - Terminal color support
- `github.com/mattn/go-isatty` - TTY detection

## Architecture Patterns
- Standard Go project layout with `cmd/` and `internal/`
- Cobra for CLI command structure
- Dependency injection via constructor functions (e.g., `NewEngine(cfg)`)
- Internal packages to prevent external imports
