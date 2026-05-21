package services

import (
	"context"
	"fmt"
	"strings"
)

// InteractshTool wraps interactsh-client for OOB vulnerability testing.
type InteractshTool struct{}

func (t *InteractshTool) Name() string {
	return "interactsh"
}

func (t *InteractshTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	// Interactsh is usually used to generate a payload URL or monitor for interactions.
	// For this adapter, we will use it to generate a unique session and return it.

	args := []string{"-silent", "-n", "1"}
	lines, err := RunCommandLines(ctx, "interactsh-client", args...)
	if err != nil {
		return nil, fmt.Errorf("interactsh execution failed: %w", err)
	}

	url := ""
	if len(lines) > 0 {
		url = strings.TrimSpace(lines[0])
	}
	if url == "" {
		return nil, fmt.Errorf("interactsh returned no URL")
	}

	return []Event{
		NewEvent(url, t.Name(), "oob_session", map[string]string{
			"description": "Unique Interactsh OOB session generated",
		}),
	}, nil
}
