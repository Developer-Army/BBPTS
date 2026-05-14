package recon

import (
	"context"
	"fmt"
	"strings"
)

type KatanaTool struct{}

func (t *KatanaTool) Name() string {
	return "katana"
}

func (t *KatanaTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-list", "-", "-c", fmt.Sprintf("%d", threads)}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "katana", args...)
	if err != nil {
		return nil, fmt.Errorf("katana execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"endpoint": value}
	}), nil
}
