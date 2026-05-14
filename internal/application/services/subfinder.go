package services

import (
	"context"
	"fmt"
)

type SubfinderTool struct{}

func (t *SubfinderTool) Name() string {
	return "subfinder"
}

func (t *SubfinderTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-t", fmt.Sprintf("%d", threads)}
	for _, target := range targets {
		args = append(args, "-d", target)
	}
	lines, err := RunCommandLines(ctx, "subfinder", args...)
	if err != nil {
		return nil, fmt.Errorf("subfinder execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"source_target": value}
	}), nil
}
