# Hooksy - Task Completion Checklist

When completing a task, ensure the following steps are performed:

## Before Committing

### 1. Build
```bash
make build
```
Ensure the binary builds successfully.

### 2. Tests
```bash
make test
```
All unit tests should pass.

### 3. Integration Tests
```bash
make test-integration
```
Verify integration tests pass (requires binary to be built first).

### 4. Linting
```bash
make lint
```
Run `go vet` and `golint`. Fix any issues.

### 5. Config Validation
```bash
make validate
```
Validate all config files in `configs/`.

## Code Quality Checks

- [ ] No hardcoded secrets or credentials
- [ ] Error handling with wrapped errors (`%w`)
- [ ] Exported functions have doc comments
- [ ] New CLI commands added to README if applicable
- [ ] Configuration changes documented

## If Adding New Features

- [ ] Update README.md usage section
- [ ] Update PLAN.md implementation status if applicable
- [ ] Add example config if introducing new rule types
- [ ] Consider adding integration test cases
