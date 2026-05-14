package recon

import (
	"context"
	"fmt"
	"strings"
)

type ChaosTool struct{}

func (t *ChaosTool) Name() string {
	return "chaos"
}

func (t *ChaosTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-list", "-", "-t", fmt.Sprintf("%d", threads)}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "chaos", args...)
	if err != nil {
		return nil, fmt.Errorf("chaos execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"enrichment": value}
	}), nil
}
