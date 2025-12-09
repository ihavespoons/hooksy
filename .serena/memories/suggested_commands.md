# Hooksy - Suggested Commands

## Build & Install

```bash
# Build the binary locally
make build

# Install to $GOPATH/bin
make install

# Build for all platforms (darwin, linux, windows)
make release
```

## Testing

```bash
# Run unit tests
make test

# Run integration tests (requires built binary)
make test-integration

# Run tests with verbose output
go test -v ./...
```

## Linting & Validation

```bash
# Run go vet and golint
make lint

# Validate config files
make validate

# Validate a specific config
./hooksy validate --config configs/default.yaml
```

## Development

```bash
# Run hooksy commands directly during development
go run ./cmd/hooksy <command>

# Example: inspect a hook event
echo '{"tool_name": "Bash", "tool_input": {"command": "ls"}}' | go run ./cmd/hooksy inspect --event PreToolUse

# Clean build artifacts
make clean
```

## CLI Commands

```bash
# Initialize config (project-level)
./hooksy init

# Initialize config (global)
./hooksy init --global

# Validate configuration
./hooksy validate

# List active rules
./hooksy rules list

# Test a rule
./hooksy rules test --event PreToolUse --input sample.json

# Generate Claude Code hooks config
./hooksy generate-hooks --events PreToolUse,PostToolUse

# Inspect with verbose logging
./hooksy inspect --event PreToolUse --verbose
```

## System Utilities (macOS/Darwin)

```bash
# Git
git status
git log --oneline -10

# Find files
find . -name "*.go"

# Search in files
grep -r "pattern" .

# List directory
ls -la
```
