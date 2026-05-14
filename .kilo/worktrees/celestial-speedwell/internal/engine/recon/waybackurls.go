package recon

import (
	"context"
	"fmt"
	"strings"
)

type WaybackurlsTool struct{}

func (t *WaybackurlsTool) Name() string {
	return "waybackurls"
}

func (t *WaybackurlsTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "waybackurls", args...)
	if err != nil {
		return nil, fmt.Errorf("waybackurls execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"history_url": value}
	}), nil
}
