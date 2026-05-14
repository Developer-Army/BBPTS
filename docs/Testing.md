# Testing Guide - BBPTS v1.0

This document covers the testing strategy, test organization, and running tests for BBPTS.

## Table of Contents

- [Test Overview](#test-overview)
- [Running Tests](#running-tests)
- [Test Structure](#test-structure)
- [Writing Tests](#writing-tests)
- [Continuous Integration](#continuous-integration)
- [Performance Testing](#performance-testing)

## Test Overview

BBPTS maintains comprehensive test coverage across multiple levels:

- **Unit Tests**: Individual functions and methods
- **Integration Tests**: Component interactions
- **End-to-End Tests**: Complete pipeline workflows
- **Benchmark Tests**: Performance validation

### Coverage Goals

- **Core Packages**: 90%+ coverage
- **Engine Packages**: 85%+ coverage
- **UI Packages**: 70%+ coverage
- **Integration Tests**: 80%+ coverage

## Running Tests

### All Tests

```bash
# Run complete test suite
go test ./...

# With coverage report
go test -cover ./...

# With detailed coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Specific Packages

```bash
# Core functionality
go test ./internal/core/...

# Analysis engine
go test ./internal/analysis/...

# Recon tools
go test ./internal/engine/recon/...

# Integration tests
go test ./internal/app/...
```

### Test Options

```bash
# Verbose output
go test -v ./...

# Race detection
go test -race ./...

# Benchmark tests
go test -bench=. ./...

# Timeout control
go test -timeout=30s ./...

# Specific test functions
go test -run TestSpecificFunction ./...
```

## Test Structure

### Unit Tests

Located alongside source code with `_test.go` suffix:

```
internal/analysis/analyze/
├── insights.go
├── insights_test.go
├── report.go
└── report_test.go
```

### Integration Tests

Full pipeline testing in `internal/app/integration_test.go`:

- **Pipeline Execution**: End-to-end workflow validation
- **Multi-stage Processing**: Sequential stage execution
- **Error Handling**: Timeout and failure scenarios
- **Tool Integration**: External tool coordination

### Test Categories

#### Core Tests
- Configuration parsing
- Input validation
- Data normalization
- State management

#### Engine Tests
- Tool orchestration
- Concurrency control
- Error recovery
- Pipeline staging

#### Analysis Tests
- Risk scoring algorithms
- Tag assignment logic
- Insight generation
- Report formatting

#### Integration Tests
- Complete workflow execution
- External tool integration
- Performance validation
- Error propagation

## Writing Tests

### Unit Test Example

```go
package analyze

import (
    "testing"
    "github.com/Developer-Army/BBPTS/internal/engine/recon"
)

func TestParameterAnalyzer(t *testing.T) {
    tests := []struct {
        name     string
        target   string
        expected []string
    }{
        {
            name:     "SQL injection candidate",
            target:   "https://example.com/search?id=1",
            expected: []string{"sqli-candidate"},
        },
        // Add more test cases
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            insight := &Insight{}
            analyzer := &ParameterAnalyzer{}

            event := recon.Event{Target: tt.target}
            analyzer.Analyze(event, insight)

            for _, tag := range tt.expected {
                if !contains(insight.Tags, tag) {
                    t.Errorf("Expected tag %s not found in %v", tag, insight.Tags)
                }
            }
        })
    }
}

func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
```

### Integration Test Example

```go
func TestFullPipelineIntegration(t *testing.T) {
    // Setup test environment
    tempDir, err := os.MkdirTemp("", "bbpts_integration_test")
    if err != nil {
        t.Fatalf("Failed to create temp dir: %v", err)
    }
    defer os.RemoveAll(tempDir)

    // Create test targets
    targetsFile := filepath.Join(tempDir, "targets.txt")
    if err := os.WriteFile(targetsFile, []byte("example.com\n"), 0644); err != nil {
        t.Fatalf("Failed to write targets file: %v", err)
    }

    // Configure minimal test setup
    opts := Options{
        Input:     targetsFile,
        Threads:   1,
        Timeout:   5 * time.Second,
        LowResource: true,
    }

    // Execute pipeline
    events, err := runPipelineWithOptions(opts)
    if err != nil {
        t.Fatalf("Pipeline execution failed: %v", err)
    }

    // Validate results
    if len(events) == 0 {
        t.Error("Expected at least one event from pipeline")
    }

    // Check for expected event types
    hasDomainEvent := false
    for _, event := range events {
        if event.Type == "domain_found" {
            hasDomainEvent = true
            break
        }
    }

    if !hasDomainEvent {
        t.Error("Expected domain_found event in pipeline output")
    }
}
```

### Test Helpers

Common testing utilities in `internal/testutil/`:

```go
// testutil/helpers.go
func CreateTestEvent(target, source, eventType string) recon.Event {
    return recon.Event{
        Target: target,
        Source: source,
        Type:   eventType,
        Properties: map[string]string{
            "test": "true",
        },
    }
}

func AssertInsightHasTag(t *testing.T, insight *Insight, expectedTag string) {
    for _, tag := range insight.Tags {
        if tag == expectedTag {
            return
        }
    }
    t.Errorf("Expected tag %s not found in insight tags: %v", expectedTag, insight.Tags)
}
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    - uses: actions/setup-go@v4
      with:
        go-version: '1.22'

    - name: Cache dependencies
      uses: actions/cache@v3
      with:
        path: ~/go/pkg/mod
        key: ${{ runner.os }}-go-${{ hashFiles('**/go.sum') }}

    - name: Run tests
      run: go test -v -race -coverprofile=coverage.out ./...

    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks
go install honnef.co/go/tools/cmd/staticcheck@latest
go install golang.org/x/lint/golint@latest

# Run checks
go vet ./...
staticcheck ./...
golint ./...
go test ./...
```

## Performance Testing

### Benchmark Tests

```go
func BenchmarkInsightGeneration(b *testing.B) {
    targets := []string{"example.com", "test.com", "demo.com"}
    events := generateTestEvents(100)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        DeriveInsights(targets, events)
    }
}

func BenchmarkOrchestratorRun(b *testing.B) {
    orchestrator := NewOrchestrator(Config{Threads: 4})
    targets := generateLargeTargetList(1000)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        orchestrator.Run(context.Background(), targets, 4)
    }
}
```

### Load Testing

```bash
# Test with large target sets
go test -bench=BenchmarkLargeScale -benchtime=30s ./internal/engine/recon/

# Memory profiling
go test -bench=BenchmarkMemoryUsage -benchmem ./...

# CPU profiling
go test -bench=BenchmarkCPUUsage -cpuprofile=cpu.out ./...
go tool pprof cpu.out
```

### Performance Metrics

Key performance indicators:

- **Pipeline Throughput**: Events processed per second
- **Memory Usage**: Peak memory consumption
- **CPU Utilization**: Core usage during scanning
- **Response Time**: Time to complete full reconnaissance

### Profiling

```bash
# Generate profiles
go test -cpuprofile=cpu.prof -memprofile=mem.prof ./...

# Analyze profiles
go tool pprof cpu.prof
go tool pprof mem.prof
```

## Test Data Management

### Test Fixtures

Store test data in `testdata/` directories:

```
internal/analysis/analyze/
├── testdata/
│   ├── sample_events.json
│   └── expected_insights.json
```

### Mock Services

For external dependencies:

```go
type MockHTTPClient struct {
    responses map[string]*http.Response
}

func (m *MockHTTPClient) Do(req *http.Request) (*http.Response, error) {
    if resp, ok := m.responses[req.URL.String()]; ok {
        return resp, nil
    }
    return &http.Response{StatusCode: 404}, nil
}
```

## Troubleshooting Tests

### Common Issues

**Flaky Tests:**
- Use proper cleanup in `defer` statements
- Avoid relying on external services
- Use deterministic test data

**Slow Tests:**
- Mock external dependencies
- Use smaller test datasets
- Parallelize independent tests

**Race Conditions:**
- Run with `-race` flag
- Use proper synchronization
- Avoid shared state between tests

**Coverage Issues:**
- Test error paths
- Cover edge cases
- Use table-driven tests for comprehensive coverage

### Debugging Failed Tests

```bash
# Run single test with verbose output
go test -v -run TestSpecificFunction ./package

# Debug with delve
dlv test ./package

# Check test logs
go test -v 2>&1 | tee test.log
```

This testing guide ensures BBPTS maintains high quality and reliability through comprehensive automated testing.

### ✅ Updated Tool Selection System
- **Default Behavior**: All available tools now run by default (no default limit to httpx,crtsh)
- **Tool Flags Added**:
  - `--tools <list>` — Specify comma-separated tools (e.g., `--tools subfinder,httpx,naabu`)
  - `--tool <list>` — Short form of --tools
  - `-t <list>` — Shortest form
  - Leave empty to run all tools

### Example Usage:
```bash
# Run all available tools (default)
./bbpts -i targets.csv

# Run specific tools
./bbpts -i targets.csv --tools subfinder,httpx,naabu
./bbpts -i targets.csv -t katana,nuclei,ffuf
```

## Updated Pipeline Stages (Optimized for Bug Bounty)

**FIXED**: Pipeline stages reorganized to skip fake websites and focus on real vulnerabilities.

### Stage Changes:
- **Stage 0**: Preprocessing (uro)
- **Stage 1**: Passive & DNS Recon (amass, assetfinder, crtsh, subfinder, chaos, puredns)
- **Stage 2**: Active Probing - Ports & Web (dnsx, naabu, httpx) - *COMBINED & OPTIMIZED*
  - Naabu now targets vulnerable ports only: 20,21,22,23,25,53,67,68,80,110,119,123,137,138,139,143,161,162,389,443,445,465,514,587,631,636,993,995,1433,1434,1521,2049,3306,3389,3690,5432,5900,5984,6379,6660-6669,8000,8080,8443,8888,9000,9092,9200,9300,11211,27017,27018,27019,50000,50070,50075,61616
- **Stage 3**: Crawling & URL Discovery (katana, waybackurls, gau, hakrawler)
- **Stage 4**: Directory Fuzzing (ffuf, gobuster, feroxbuster)
- **Stage 5**: Vulnerability Verification (nuclei, interactsh, dalfox)

### Key Improvements:
✅ Fixed httpx concurrency flag from `-threads` to `-c`
✅ All tools run by default instead of hardcoded subset
✅ Tool selection via flags: `--tools`, `--tool`, `-t`
✅ Eliminated Stage 3 (Web Probing) - merged into Stage 2 for efficiency
✅ Added curated vulnerable port list to Naabu for targeted scanning
✅ Reduced time wasted on fake/non-vulnerable websites
✅ Sequential execution: 0 → 1 → 2 → 3 → 4 → 5

---

## Previous Test Output Reference

Subfinder Running
-------------------------- this line will contain the url instead of ------------------ going through one by one and then it should be like at the end it says ____ url found and somewhat likewise for all the others tools.
dev-army@Water-Hydra:~/Bug_Bounty/Setup$ ./bbpts -i targets.csv
2026/05/06 13:35:49 INFO starting pipeline stage stage=1 tools=1 targets=1 fleet_mode=false
    / __  / __  / /_/ / / /  \__ \             
   / /_/ / /_/ / ____/ / /  ___/ /             
  /_____/_____/_/     /_/  /____/  v2.0-ELITE  
                                               
   ⣯  SCANNING Stage 1 (1 tools, 1 targets)    
  ╭────────────────────────────────────────╮   
  │       / __ )/ __ )/ __ \/_  __/ ___/  𝓪𝓷𝓪𝓵𝔂𝔃𝓮𝓻  
    / __  / __  / /_/ / / /  \__ \             
   / /_/ / /_/ / ____/ / /  ___/ /             
  /_____/_____/_/     /_/  /____/  v2.0-ELITE  
                                               
2026/05/06 13:36:06 INFO pipeline stage complete stage=1 events_found=0 cascaded_targ
  │  EVENTS: 0 | INSIGHTS: 1 | CRITICAL: 0 │   
     2026/05/06 13:36:06 INFO starting pipeline stage stage=2 tools=1 targets=1 fleet
_mode=false
2026/05/06 13:36:06 INFO pipeline stage complete stage=2 events_found=0 cascaded_targ
   13:36:09 IST | press 'q' to exit            
dev-army@Water-Hydra:~/Bug_Bounty/Setup$ ^C