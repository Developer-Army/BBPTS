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

BBPTS utilizes a modular adapter design where tools are wrapped by Go structs implementing the `Tool` interface. 

### Step 1: Implement the Tool Interface
Create a new file in `internal/application/services/yourtool.go`. Utilize the pipeline execution helper functions (`RunCommandWithInputLines` or `RunCommandLines`) and event parsing helpers (`NewEventsFromLines` or `NewEventsFromLinesFunc`):

```go
package services

import (
	"context"
	"fmt"
)

// YourToolAdapter wraps the external binary execution
type YourToolAdapter struct{}

func (t *YourToolAdapter) Name() string {
	return "yourtool"
}

func (t *YourToolAdapter) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// 1. Setup CLI args
	args := []string{"-v", "-o", "-"}

	// 2. Run target binaries via orchestrator helper
	// RunCommandWithInputLines feeds targets on stdin
	lines, err := RunCommandWithInputLines(ctx, []byte(targets[0]), "yourtool", args...)
	if err != nil {
		return nil, fmt.Errorf("yourtool execution failure: %w", err)
	}

	// 3. Convert output lines into unified BBPTS Events
	return NewEventsFromLines(lines, t.Name(), map[string]string{
		"confidence": "high",
	}), nil
}
```

### Step 2: Register in the Tool Registry
Open [internal/application/services/registry.go](file:///home/dev-army/Projects/BBPTS/internal/application/services/registry.go) and add your factory to the `toolFactories` map along with its pipeline stage assignment:

```go
var toolFactories = map[string]struct {
	factory func() Tool
	stage   int
}{
	// ...
	"yourtool": {factory: func() Tool { return &YourToolAdapter{} }, stage: 3},
}
```

### Step 3: Rebuild and Verify
Run the compilation suite and run the system diagnostics script:
```bash
go build -o bbpts ./cmd/bbpts
./bbpts -doctor
go test -v ./internal/application/services/...
```

