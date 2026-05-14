package recon

import (
	"context"
	"fmt"
	"strings"
)

// PurednsTool wraps puredns for high-speed DNS resolution.
type PurednsTool struct{}

func (t *PurednsTool) Name() string {
	return "puredns"
}

func (t *PurednsTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// For resolution, we use 'resolve' mode.
	// Note: puredns usually needs a resolvers list, but we'll assume default or system setup.
	args := []string{"resolve", "--quiet", "--rate-limit", fmt.Sprintf("%d", threads*100)}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "puredns", args...)
	if err != nil {
		return nil, fmt.Errorf("puredns execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"type": "resolved"}
	}), nil
}
