# Hooksy - Code Style & Conventions

## General Go Conventions
- Standard Go formatting (gofmt)
- Standard Go project layout with `cmd/` and `internal/`
- Package names are lowercase, single words

## Naming Conventions
- **Structs**: PascalCase (e.g., `Engine`, `Config`, `Rule`)
- **Methods**: PascalCase for exported, camelCase for unexported (e.g., `Inspect`, `makeDecision`)
- **Functions**: PascalCase for exported constructors (e.g., `NewEngine`)
- **Variables**: camelCase (e.g., `configFile`, `eventType`)
- **Constants**: PascalCase for exported (e.g., `PreToolUse`)

## Struct Patterns
- Constructor pattern: `NewXxx(deps) *Xxx`
- Methods use pointer receivers: `func (e *Engine) Method()`

## Error Handling
- Wrap errors with context: `fmt.Errorf("failed to parse: %w", err)`
- Return early on error
- Log errors with structured logging

## Comments
- Exported functions have doc comments starting with function name
- Example: `// Execute runs the root command`

## Imports
- Standard library first, then third-party, then local packages
- Group imports by blank lines

## Logging
- Use zerolog structured logging
- Log levels: Debug, Info, Warn, Error
- Chain style: `logger.Debug().Str("key", "value").Msg("message")`

## CLI Structure
- Use Cobra for commands
- Global flags in root.go: `rootCmd.PersistentFlags()`
- Short (-v) and long (--verbose) flag variants
- Commands defined in separate files under `internal/cli/`

## Testing
- Use `go test -v ./...`
- Integration tests via Makefile
- Test files: `*_test.go` (none present yet, noted in roadmap)

## Config
- YAML format with snake_case keys
- Versioned config (`version: "1"`)
- Regex patterns for matching
