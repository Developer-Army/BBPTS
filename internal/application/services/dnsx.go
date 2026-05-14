package services

import (
	"context"
	"fmt"
	"strings"
)

type DNSXTool struct{}

func (t *DNSXTool) Name() string {
	return "dnsx"
}

func (t *DNSXTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-t", fmt.Sprintf("%d", threads)}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "dnsx", args...)
	if err != nil {
		return nil, fmt.Errorf("dnsx execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"dns_entry": value}
	}), nil
}
