package recon

import (
	"context"
	"fmt"
	"strings"
)

type GauTool struct{}

func (t *GauTool) Name() string {
	return "gau"
}

func (t *GauTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-t", fmt.Sprintf("%d", threads)}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "gau", args...)
	if err != nil {
		return nil, fmt.Errorf("gau execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"history_url": value}
	}), nil
}
