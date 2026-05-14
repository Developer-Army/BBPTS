package recon

import (
	"context"
	"fmt"
	"strings"
)

type SubfinderTool struct{}

func (t *SubfinderTool) Name() string {
	return "subfinder"
}

func (t *SubfinderTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-dL", "-", "-t", fmt.Sprintf("%d", threads)}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "subfinder", args...)
	if err != nil {
		return nil, fmt.Errorf("subfinder execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"source_target": value}
	}), nil
}
