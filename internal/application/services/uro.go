package services

import (
	"context"
	"fmt"
	"strings"
)

// UroTool wraps the Python tool for URL normalization and deduplication.
type UroTool struct{}

func (t *UroTool) Name() string {
	return "uro"
}

func (t *UroTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// uro takes URLs via stdin and outputs cleaned URLs.
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "uro")
	if err != nil {
		return nil, fmt.Errorf("uro execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"type": "cleaned_url"}
	}), nil
}
