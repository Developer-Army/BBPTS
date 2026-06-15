# Development Guide - BBPTS v1.4.0

This guide covers development setup, architecture, and contribution guidelines for BBPTS.

## Table of Contents

- [Development Setup](#development-setup)
- [Project Architecture](#project-architecture)
- [Code Organization](#code-organization)
- [Testing](#testing)
- [Contributing](#contributing)
- [Release Process](#release-process)

## Development Setup

### Prerequisites

- Go 1.22 or later
- Git
- Make (optional, for convenience)

### Setup Steps

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Developer-Army/BBPTS.git
   cd BBPTS
   ```

2. **Install dependencies**:

   ```bash
   go mod download
   ```

3. **Run setup script** (installs external tools):

   ```bash
   bash scripts/setup.sh
   ```

4. **Build the project**:

   ```bash
   go build -o bbpts ./cmd/bbpts
   ```

5. **Run diagnostics**:

   ```bash
   ./bbpts -doctor
   ```

6. **Run tests**:
   ```bash
   go test ./...
   ```

### Development Workflow

1. Create a feature branch: `git checkout -b feature/your-feature`
2. Make changes and add tests
3. Run tests: `go test ./...`
4. Build and test manually: `go build -o bbpts ./cmd/bbpts && ./bbpts -doctor`
5. Commit changes: `git commit -am "Add your feature"`
6. Push and create PR

## Project Architecture

BBPTS follows a layered architecture designed for maintainability and extensibility:

```
┌─────────────────────────────────────────────────────┐
│              User Interfaces (ui/)                  │
│  ┌──────────────────┬──────────────┬──────────────┐
│  │   Terminal UI    │   Reports    │   Server API │
│  │   (TUI)          │   (HTML/MD)  │   (REST)     │
│  └──────────────────┴──────────────┴──────────────┘
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│             Engine & Processing (engine/)           │
│  ┌──────────────┬──────────────┬──────────────────┐
│  │   Recon      │  Analysis    │  Integration     │
│  │ (Orchest.)   │  (Scoring)   │ (Burp/Caido/ZAP)│
│  └──────────────┴──────────────┴──────────────────┘
└─────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────┐
│           Core Infrastructure (core/)               │
│  ┌──────────┬──────────┬───────┬──────────────────┐
│  │ Config   │ Storage  │ State │ Notifications    │
│  │ Loading  │ (SQLite) │ Diff  │ (Discord/Slack)  │
│  └──────────┴──────────┴───────┴──────────────────┘
└─────────────────────────────────────────────────────┘
```

### Key Design Principles

- **Separation of Concerns**: Each layer has a specific responsibility
- **Event-Driven**: Internal bus for loose coupling between components
- **Concurrent**: Panic-safe orchestration with semaphores
- **Testable**: Comprehensive unit and integration tests
- **Configurable**: JSON-based configuration with environment overrides

## Code Organization

### Directory Structure

```
bbpts/
├── cmd/bbpts/              # Application entry point (main.go)
├── internal/
│   ├── application/        # Application orchestrators & services (orchestrator, browser, escalator)
│   ├── domain/             # Core business models & logic
│   │   ├── analysis/       # Risk analysis, heuristics, & scoring
│   │   ├── assets/         # Asset nodes, graph models, & mapping
│   │   ├── findings/       # Vulnerability finding models & schemas
│   │   ├── ownership/      # Asset custodianship & ownership mapping
│   │   ├── recon/          # Passive/active tool contracts & events
│   │   ├── risk/           # 7-factor evidence-based risk engine
│   │   ├── security/       # Input validation, sanitization, & SSRF protection
│   │   └── workflows/      # [Experimental] CTEM compliance state machine
│   ├── infrastructure/     # Database (SQLite), messaging (NATS), & browser automation
│   ├── interfaces/         # Entry points (CLI app, Web server, Terminal UI, distributed workers)
│   └── shared/             # Configurations, input parsers, normalizers, & helpers
├── configs/                # Default configuration files
├── docs/                   # Documentation
├── scripts/                # Setup and utility scripts
└── wordlists/              # Default wordlists
```

### Key Files

#### `cmd/bbpts/main.go`
- Application entry point.
- CLI flag parsing & configuration bootstrap.

#### `internal/interfaces/cli/app.go`
- Main application scan orchestration loops.
- TUI bridge coordination & worker node launcher.

#### `internal/application/services/orchestrator.go`
- Concurrent tool execution pipeline management.
- Rate limiting & event-bus dispatching.

#### `internal/domain/analysis/analyze/insights.go`
- Risk scoring algorithms.
- Recommendation checklists & evidence accumulation.

### Domain Modules & Release Integration Status

#### `internal/domain/security/`
- **Active / Fully Integrated**: Contains active input sanitization and `IsPrivateIP`/`IsPrivateAddr` checks to prevent Server-Side Request Forgery (SSRF) in stealth client dialers and target validation.

#### `internal/domain/workflows/`
- **Experimental / Not Yet Fully Integrated**: Contains the core state machine rules and SLA breach compliance transition logic. While the module has 100% test coverage, it is *not* currently wired into the CLI scanner workflow pipeline for the v1.4.0 release. It is placed here for developer preview and future extension.

### Coding Standards
- **Go Standards**: Follow standard Go conventions.
- **Documentation**: All exported functions must have comments.
- **Error Handling**: Use explicit error returns, no panics.
- **Logging**: Use structured logging with slog.
- **Testing**: 80%+ code coverage target.
- **Imports**: Group standard library, then third-party, then internal.

## Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package
go test ./internal/analysis/...

# Run with verbose output
go test -v ./...
```

### Test Structure

- **Unit Tests**: Test individual functions and methods
- **Integration Tests**: Test component interactions
- **End-to-End Tests**: Test complete workflows
- **Benchmark Tests**: Performance testing

### Writing Tests

```go
func TestMyFunction(t *testing.T) {
    // Arrange
    input := "test input"
    expected := "expected output"

    // Act
    result := MyFunction(input)

    // Assert
    if result != expected {
        t.Errorf("MyFunction(%q) = %q, want %q", input, result, expected)
    }
}
```

### Test Coverage

Current coverage targets:

- Core packages: 90%+
- UI packages: 70%+
- Integration tests: 80%+

## Contributing

### Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes
4. **Add** tests for new functionality
5. **Ensure** all tests pass
6. **Update** documentation if needed
7. **Commit** with clear messages
8. **Push** to your fork
9. **Create** a Pull Request

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

Types:

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Testing
- `chore`: Maintenance

### Code Review Checklist

- [ ] Code follows Go standards
- [ ] Functions are properly documented
- [ ] Tests are included and pass
- [ ] No breaking changes without discussion
- [ ] Performance impact considered
- [ ] Security implications reviewed

## Release Process

### Version Numbering

BBPTS follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

### Release Steps

1. **Update version** in relevant files
2. **Update CHANGELOG.md** with changes
3. **Run full test suite**
4. **Create release branch**
5. **Tag release**: `git tag v1.0.0`
6. **Create GitHub release**
7. **Update documentation**

### Pre-release Checklist

- [ ] All tests pass
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Breaking changes documented
- [ ] Performance benchmarks run
- [ ] Security review completed

## Support

For development questions:

- Open an issue on GitHub
- Join our Discord community
- Check the documentation

## License

By contributing to BBPTS, you agree that your contributions will be licensed under the MIT License.

### `internal/engine/analysis/`

- **insights.go**: Risk scoring and prioritization
- **analyze/**: Detailed analysis components
- Tests cover: insight generation, prioritization, tagging

### `internal/engine/integration/`

- **exporter.go**: Burp/Caido export
- **tools.go**: ZAP, extended Burp, proxy feeder, webhooks
- Tests cover: all export formats, proxy rotation

### `internal/core/`

- **config/config.go**: Configuration loading and management
- **input/parser.go**: CSV/text parsing with metadata
- **state/state.go**: Database-backed state and differential scanning
- **storage/db.go**: SQLite operations
- **notify/**: Notification delivery (Discord, Slack, Telegram)
- **ratelimit/**: Request throttling

### `internal/ui/report/`

- **report.go**: Comprehensive report generation
- **burp.go**: Burp-specific formatting
- **markdown.go**: Markdown formatting
- **terminal.go**: Terminal output

## Testing Strategy

### Unit Tests

Each package has a `*_test.go` file covering:

- Happy path scenarios
- Edge cases (empty inputs, invalid data)
- Error conditions
- Timeout handling

### Integration Tests

Files ending in `_integration_test.go` cover:

- Multi-component workflows
- End-to-end scenarios
- Tool integration

### Running Tests

```bash
# All tests
make test

# Specific package
go test ./internal/core/input/...

# Verbose
go test -v ./...

# With coverage
go test -cover ./...

# Specific test
go test -run TestParserCSVBasic ./internal/core/input/
```

## Recommended Test Execution Plans

### 1. Quick Validation (< 1 minute)

Run before committing code:

```bash
# All tests with summary
go test ./...

# Or with make
make test
```

**Validates:** Basic functionality across all packages

### 2. Development Testing (Before Submit)

Run while developing features:

```bash
# Tests + coverage
go test -v -cover ./...

# Tests + race detection
go test -race ./...

# Tests + timeout (catches hanging tests)
go test -timeout 30s ./...
```

**Validates:** No race conditions, tests complete, coverage maintained

### 3. Pre-Release Testing

Run before releasing a version:

```bash
# Full test suite with detailed output
go test -v -race -timeout 60s -coverprofile=coverage.out ./...

# Check coverage profile
go tool cover -html=coverage.out -o coverage.html

# Show coverage by package
go tool cover -func=coverage.out
```

**Validates:** All tests pass, no races, coverage adequate

### 4. Package-Specific Testing

**Input Parsing (Critical for CSV handling):**

```bash
go test -v ./internal/core/input/...
```

Tests to verify:

- `TestParserCSVBasic` - CSV format parsing
- `TestParserNewlineFormat` - Line-separated format
- `TestParserComments` - Comment filtering
- `TestParserWhitespaceHandling` - Trimming
- `TestParserQuotedCSVFields` - Quoted fields
- `TestParserEmptyFile` - Edge case handling
- `TestParserNonexistentFile` - Error handling

**Orchestrator (Core engine):**

```bash
go test -v ./internal/engine/recon/
```

Tests to verify:

- `TestOrchestratorInitialization` - Setup works
- `TestOrchestratorExecutionTimeout` - Respects timeouts
- `TestOrchestratorWithInvalidTools` - Error handling
- `TestOrchestratorConcurrency` - Thread safety
- `TestOrchestratorRateLimiting` - Rate limiting works

**State Management (Persistence):**

```bash
go test -v ./internal/core/state/
```

Tests to verify:

- `TestStateInitialization` - DB creation
- `TestStateAssetStorage` - Asset persistence
- `TestStateDifferential` - Diff detection
- `TestStateMultipleTargets` - Bulk operations

**Analysis (Scoring & Insights):**

```bash
go test -v ./internal/analysis/analyze/
```

Tests to verify:

- `TestInsightsGenerationBasic` - Insight creation
- `TestInsightsPriorityLevels` - Priority assignment
- `TestInsightsTagging` - Tag generation
- `TestInsightsSuggestedTests` - Test recommendations
- `TestInsightsEvidenceAccumulation` - Evidence counting

**Integration (Tool Exports):**

```bash
go test -v ./internal/engine/integration/
```

Tests to verify:

- `TestBurpExportIntegration` - Burp export works
- `TestCaidoExportIntegration` - Caido export works
- `TestZAPExportIntegration` - ZAP export works
- `TestProxyFeederRotation` - Proxy rotation
- `TestMultipleToolExportIntegration` - Multi-tool workflow

**Reports (Output Generation):**

```bash
go test -v ./internal/ui/report/
```

Tests to verify:

- `TestJSONReportGeneration` - JSON output
- `TestMarkdownReportGeneration` - Markdown output
- `TestHTMLReportGeneration` - HTML output
- `TestReportWithMultipleSeverities` - Severity handling
- `TestReportFiltering` - Score filtering

### 5. Scenario-Based Testing

**CSV Input Workflow:**

```bash
# Run these in sequence
go test -v -run "Parser" ./internal/core/input/
go test -v -run "Insights" ./internal/analysis/analyze/
go test -v -run "Report" ./internal/ui/report/
```

**Tool Orchestration Workflow:**

```bash
# Run these in sequence
go test -v -run "Orchestrator" ./internal/engine/recon/
go test -v -run "Runner" ./internal/engine/recon/
go test -v -run "RateLimiting" ./internal/engine/recon/
```

**Multi-Tool Export Workflow:**

```bash
# Run these in sequence
go test -v -run "BurpExport|CaidoExport|ZAPExport" ./internal/engine/integration/
go test -v -run "ProxyFeeder|WebhookNotifier" ./internal/engine/integration/
```

### 6. Continuous Integration (CI/CD)

Add to CI pipeline:

```bash
#!/bin/bash
set -e

echo "1. Running all tests..."
go test -v -race -timeout 60s ./... 2>&1 | tee test-results.txt

echo "2. Checking coverage..."
go test -coverprofile=coverage.out ./...
COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
echo "Coverage: ${COVERAGE}%"

if (( $(echo "$COVERAGE < 70" | bc -l) )); then
    echo "Coverage below 70%!"
    exit 1
fi

echo "3. Running linters..."
go fmt ./...
go vet ./...

echo " All checks passed!"
```

### 7. Regression Testing

When fixing bugs, run:

```bash
# Run all tests
go test -v ./...

# Run with race detector
go test -race ./...

# Run affected package + integration tests
go test -v ./internal/[affected-package]/...
go test -v ./internal/*/integration_test.go
```

## Test Coverage Goals

| Package            | Current | Target | Priority |
| ------------------ | ------- | ------ | -------- |
| input/parser       | 95%+    | 95%+   | Critical |
| engine/recon       | 80%+    | 85%+   | High     |
| core/state         | 85%+    | 90%+   | High     |
| analysis/analyze   | 85%+    | 90%+   | High     |
| engine/integration | 70%+    | 80%+   | Medium   |
| ui/report          | 75%+    | 85%+   | Medium   |

## Test Naming Convention

Tests follow this pattern:

- `Test[Component][Scenario]` - Unit test
- `Test[Component][Scenario]Integration` - Integration test
- `Test[Feature]With[Condition]` - Conditional tests
- `TestMultiple[Features]` - Multi-component tests

Examples:

- `TestParserCSVBasic` - Parser + CSV + basic scenario
- `TestOrchestratorExecutionTimeout` - Orchestrator + execution + timeout
- `TestBurpExportIntegration` - Burp + export + integration
- `TestMultipleRunnersSequential` - Multiple + sequential

## Test Troubleshooting

### Flaky Tests

If a test fails intermittently:

```bash
# Run multiple times
for i in {1..10}; do go test -run TestName ./package/; done

# Run with verbose
go test -v -run TestName -timeout 30s ./package/
```

### Slow Tests

If tests are too slow:

```bash
# Find slowest tests
go test -v -timeout 60s ./... 2>&1 | grep -E "^--- |PASS|FAIL"

# Run specific slow test
go test -v -run SlowTestName -timeout 120s ./package/
```

### Failed Tests

If a test fails:

```bash
# Run with verbose output
go test -v -run FailedTest ./package/

# Run with debugging
go test -v -run FailedTest -debug ./package/
```

## Code Quality Standards

### Documentation

- All public functions have docstrings
- Complex logic has inline comments
- Examples provided where helpful
- Package-level comments explain purpose

### Error Handling

- Use `fmt.Errorf` with `%w` for error wrapping
- Check errors immediately after operations
- Provide context in error messages
- Don't suppress errors with `_`

### Naming

- Use clear, descriptive names
- Exported symbols start with capital letter
- Unexported symbols start with lowercase
- Avoid single-letter variables (except `i`, `j` in loops)

### Formatting

- Use `gofmt` - run `make fmt` if available
- Max line length: 100 characters (soft limit)
- Indentation: tabs (Go standard)

### Testing

- Each public function should have a test
- Use table-driven tests for multiple scenarios
- Include edge cases and error paths
- Clear test names indicating what's tested

## Adding New Tools

### Step 1: Create Tool Implementation

File: `internal/engine/recon/newTool.go`

```go
package recon

import "context"

type NewToolRunner struct {
    config map[string]string
}

func (n *NewToolRunner) Run(ctx context.Context, targets []string) ([]Event, error) {
    // Implementation
    return events, nil
}
```

### Step 2: Register Tool

File: `internal/engine/recon/registry.go`

```go
func GetToolByName(name string) (Tool, error) {
    switch name {
    case "newTool":
        return &NewToolRunner{}, nil
    // ...
    }
}
```

### Step 3: Add Tests

File: `internal/engine/recon/newTool_test.go`

```go
func TestNewToolRunnerExecution(t *testing.T) {
    // Test implementation
}
```

### Step 4: Update Documentation

- Add to `docs/tools.md`
- Update `README.md`
- Add examples to `QUICKSTART.md`

## Adding New Report Format

### Step 1: Create Exporter

File: `internal/ui/report/newFormat.go`

```go
func ExportToNewFormat(filename string, report *Report) error {
    // Format conversion
    return os.WriteFile(filename, data, 0644)
}
```

### Step 2: Integrate into ReportGenerator

File: `internal/ui/report/report.go`

```go
func (rg *ReportGenerator) exportForNewTool(report *Report) error {
    return ExportToNewFormat(outputPath, report)
}
```

### Step 3: Add Tests

File: `internal/ui/report/newFormat_test.go`

```go
func TestNewFormatExport(t *testing.T) {
    // Test implementation
}
```

## Performance Considerations

### Concurrency

- Use semaphores to limit concurrent operations
- Ensure panic recovery for goroutines
- Test with `TestOrchestrator*` tests

### Memory

- Stream large result sets when possible
- Use buffered channels appropriately
- Profile with `go tool pprof` if needed

### Rate Limiting

- Respect `Config.RateLimit`
- Use `ratelimit.Limiter` for distribution
- Test with `TestOrchestratorRateLimiting`

## Common Tasks

### Adding a Configuration Option

1. Update `Config` struct in target package
2. Add flag in `parseFlags()` in main.go
3. Document in `QUICKSTART.md`
4. Add test case

### Fixing a Bug

1. Write a failing test that reproduces the bug
2. Fix the bug
3. Verify test passes
4. Add regression test if needed

### Improving Documentation

1. Update relevant `.md` files
2. Add examples if applicable
3. Update version in docs
4. Test examples run correctly

## Release Process

1. **Verify Tests**: `make test`
2. **Update CHANGELOG.md**: Document changes
3. **Update Version**: In `cmd/bbpts/main.go` and README
4. **Update Docs**: Ensure all docs reflect new features
5. **Tag Release**: `git tag v2.x.x`
6. **Build**: `make build`
7. **Verify Build**: Test on multiple platforms

## Debugging Tips

### Enable Debug Logging

```bash
./bbpts -input targets.csv -debug
```

### Check Environment

```bash
./bbpts -doctor
```

### Profile Execution

```bash
go test -cpuprofile=cpu.prof ./...
go tool pprof cpu.prof
```

### Race Condition Detection

```bash
go test -race ./...
```

## Contributing Guidelines

### Before Starting

1. Check GitHub issues for related work
2. Discuss large changes with maintainers
3. Fork repository
4. Create feature branch

### While Working

1. Write tests first (TDD approach)
2. Keep commits logical and small
3. Write clear commit messages
4. Update documentation

### Before Submitting

1. Run `make test`
2. Run `make fmt`
3. Update CHANGELOG.md
4. Test on multiple OS if possible
5. Submit pull request with description

## Useful Commands

```bash
# Build
make build

# Run tests
make test

# Format code
make fmt

# Run with debug
./bbpts -input targets.csv -debug

# Run doctor diagnostics
./bbpts -doctor

# Build release binaries
make release
```

## Related Documentation

- [user_guide.md](user_guide.md) - User guide
- [user_guide.md#enhanced-csv-format](user_guide.md#enhanced-csv-format) - Input format guide
- [CHANGELOG.md](../CHANGELOG.md) - Version history
- [README.md](../README.md) - Project overview

---

## SQLite Database Schema & Fleet Synchronization

BBPTS utilizes a unified Go CGo-free SQLite engine (`modernc.org/sqlite`) for local state persistence and distributed mesh metadata tracking.

### 1. Database Schema Overview

The schema is divided into **Core Recon**, **Connected Asset Graph**, and **Enterprise CTEM** tables:

#### Core Recon Tables
* **scans**: Stores scan execution sessions (`id`, `scope`, `start_time`, `end_time`, `status`).
* **targets**: Tracks initial target lists linked to a scan (`id`, `scan_id`, `host`).
* **events**: Stores individual raw events emitted by tools (`id`, `scan_id`, `target`, `source`, `type`, `properties` JSON).

#### Connected Asset Graph Tables
* **asset_nodes**: Represents attack surface assets (`id`, `node_type`, `value`, `properties`, `scope_id`, `first_seen`, `last_seen`, `source`, `confidence`).
* **asset_edges**: Represents relationships between assets (`source_id`, `target_id`, `relation`, `first_seen`, `last_seen`, `confidence`, `observed_at`, `evidence_id`).

#### Enterprise CTEM & Ownership Tables
* **teams** / **owners**: Manages target custodianship and security escalation paths.
* **asset_ownership**: Tracks asset-to-owner mapping history.
* **finding_assignments**: Tracks the lifecycle, assignment, SLA due date, and transition status of discovered exposure findings.
* **sla_policies** / **escalation_rules**: Manages SLA compliance policy configurations and notification escalation rules.

### 2. Fleet Synchronization Architecture

For distributed multi-agent deployments, BBPTS supports secure decentralized state merging over HTTPS:

```
┌──────────────────┐               HTTP POST /api/fleet/sync               ┌──────────────────┐
│  Axiom Agent/CLI │ ────────────────────────────────────────────────────> │ Master Dashboard │
│  (Local SQLite)  │              Header: X-Sync-Token: <token>            │  (Master SQLite) │
└──────────────────┘                                                       └──────────────────┘
```

1. **State Upload**: Axiom agents or CLI runs export their local SQLite run database and stream it to the Master dashboard via `POST /api/fleet/sync`.
2. **Token Authentication**: Mutual trust is established via the `X-Sync-Token` header, matching the master's configured `fleet.sync_token`.
3. **Master Database Merge**: The master node writes the upload to a temp database and invokes `services.ImportAndMergeDatabase(masterPath, tempPath)`, performing recursive deduplication and merging:
   * Merges `scans`, `targets`, and `events` without duplicates.
   * Merges `asset_nodes` and `asset_edges`, updating `last_seen` timestamps and confidence weightings.

---

**Happy coding!**

