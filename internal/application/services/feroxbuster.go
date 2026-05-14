package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// FeroxbusterTool wraps the Rust-based fuzzer for directory discovery.
type FeroxbusterTool struct{}

func (t *FeroxbusterTool) Name() string {
	return "feroxbuster"
}

type feroxResult struct {
	URL           string `json:"url"`
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	WordCount     int    `json:"word_count"`
	LineCount     int    `json:"line_count"`
	Type          string `json:"type"`
}

func (t *FeroxbusterTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// We use --stdin to process multiple targets and --json for structured output.
	args := []string{
		"--stdin",
		"--json",
		"--silent",
		"--threads", fmt.Sprintf("%d", threads),
		"--no-recursion", // For performance on weak PCs, recursion is handled by BBPTS logic
	}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "feroxbuster", args...)
	if err != nil {
		return nil, fmt.Errorf("feroxbuster execution failed: %w", err)
	}

	events := []Event{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var res feroxResult
		if err := json.Unmarshal([]byte(line), &res); err != nil {
			continue
		}

		props := map[string]string{
			"status": fmt.Sprintf("%d", res.StatusCode),
			"length": fmt.Sprintf("%d", res.ContentLength),
			"words":  fmt.Sprintf("%d", res.WordCount),
			"lines":  fmt.Sprintf("%d", res.LineCount),
			"type":   res.Type,
		}

		events = append(events, NewEvent(res.URL, t.Name(), "directory", props))
	}

	return events, nil
}
