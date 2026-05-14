package services

import (
	"context"
	"fmt"
	"os"
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

	// Create a temporary file for targets since chaos -dL is the most reliable
	// way to scan multiple domains.
	tmpFile, err := os.CreateTemp("", "chaos-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for chaos: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(strings.Join(targets, "\n")); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write targets to temp file: %w", err)
	}
	tmpFile.Close()

	args := []string{"-silent", "-dL", tmpFile.Name()}
	key := strings.TrimSpace(GetAPIKey(ctx, "chaos"))
	if key == "" {
		// Chaos generally requires an API key; skip gracefully when not configured.
		return nil, nil
	}
	args = append(args, "-key", key)

	lines, err := RunCommandLines(ctx, "chaos", args...)
	if err != nil {
		return nil, fmt.Errorf("chaos execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"enrichment": value}
	}), nil
}
