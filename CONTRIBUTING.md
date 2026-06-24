# Contributing to BBPTS

First off, thank you for considering contributing to BBPTS! It's people like you that make BBPTS such a great tool.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- Use a clear and descriptive title for the issue to identify the problem.
- Describe the exact steps which reproduce the problem in as many details as possible.
- Provide specific examples to demonstrate the steps.

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When you are creating an enhancement suggestion, please include:

- Use a clear and descriptive title for the issue to identify the suggestion.
- Provide a step-by-step description of the suggested enhancement in as many details as possible.
- Explain why this enhancement would be useful to most BBPTS users.

### Pull Requests

- Fill in the required template
- Do not include issue numbers in the PR title
- Follow the Go coding style
- Include tests for your changes
- Ensure the test suite passes (`go test ./...`)

## Development Setup

1. Fork the repo and clone it locally
2. Ensure you have Go 1.23+ installed
3. Run `make build` to build the binary
4. Run `make test` to run the test suite
  *Note: BBPTS uses modernc.org/sqlite (pure Go, no CGo required). Run go test ./... directly.*

Thank you!

---

## Technical Walkthrough: Adding a Custom Tool Adapter

BBPTS utilizes a modular adapter design. External security and reconnaissance tools are integrated by implementing the `Tool` interface. Below is the complete step-by-step walkthrough to wire, register, configure, and test a new tool from scratch.

### Step 1: Define the Adapter
Create a new file `internal/application/services/myrecon.go`. The tool must implement the `Tool` interface:
```go
package services

import (
	"context"
	"fmt"
	"strings"
)

// MyReconAdapter wraps the external binary execution
type MyReconAdapter struct{}

func (t *MyReconAdapter) Name() string {
	return "myrecon"
}

func (t *MyReconAdapter) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// 1. Resolve rate limits, timeout, and proxy configurations from context
	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	_ = rateLimit

	// 2. Prepare CLI arguments
	args := []string{"-silent", "-json"}
	
	// Feed targets on standard input
	stdinData := []byte(strings.Join(targets, "\n"))

	// 3. Execute the binary securely using execution helper utilities
	lines, err := RunCommandWithInputLines(ctx, stdinData, "myrecon", args...)
	if err != nil {
		return nil, fmt.Errorf("myrecon binary failed: %w", err)
	}

	// 4. Convert stdout lines into unified BBPTS Event structures
	var events []Event
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Convert to discovery type event with metadata properties
		events = append(events, NewEventWithSeverity(
			line,
			t.Name(),
			"discovery",
			map[string]string{
				"tool": t.Name(),
			},
			"low",
		))
	}

	return events, nil
}
```

### Step 2: Register the Adapter in the Registry
Open [registry.go](file:///home/dev-army/Projects/BBPTS/internal/application/services/registry.go) and add your factory function to the `toolFactories` map. Assign it to one of the following reconnaissance pipeline stages:
- `0`: Subdomain Discovery (passive and active DNS enumerators)
- `1`: Host Validation & Resolution (DNS mapping, host alive check)
- `2`: Service Scanning & Port Probing (Port checking, service identification)
- `3`: Vulnerability & Parameter Fuzzing (Active parameter injection, nuclei fuzzing)

```go
var toolFactories = map[string]struct {
	factory func() Tool
	stage   int
}{
	// ...
	"myrecon": {
		factory: func() Tool { return &MyReconAdapter{} },
		stage:   0, // Stage 0 represents Subdomain Discovery
	},
}
```

### Step 3: Write a Unit Test
Create a unit test for your tool adapter in `internal/application/services/myrecon_test.go` using BBPTS test helper runners:
```go
package services

import (
	"context"
	"testing"
)

func TestMyReconAdapter(t *testing.T) {
	// Create context with API credentials and mocks
	ctx := context.Background()
	adapter := &MyReconAdapter{}

	if adapter.Name() != "myrecon" {
		t.Errorf("expected myrecon name, got %s", adapter.Name())
	}

	// We can execute a dry-run or mock execution check
	ctx = WithDryRun(ctx, true)
	events, err := adapter.Run(ctx, []string{"example.com"}, 4)
	if err != nil {
		t.Fatalf("dry run run failed: %v", err)
	}
	_ = events
}
```

### Step 4: Rebuild & Validate
Recompile the binary, run diagnostics, and check the unit test suite:
```bash
go build -o bbpts ./cmd/bbpts
./bbpts -doctor
go test -v ./internal/application/services/myrecon_test.go
```


