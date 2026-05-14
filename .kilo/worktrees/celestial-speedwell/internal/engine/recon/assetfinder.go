package recon

import (
	"context"
	"fmt"
	"strings"
)

type AssetfinderTool struct{}

func (t *AssetfinderTool) Name() string {
	return "assetfinder"
}

func (t *AssetfinderTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"--subs-only"}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "assetfinder", args...)
	if err != nil {
		return nil, fmt.Errorf("assetfinder execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"source_target": value}
	}), nil
}
