package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"strings"
)

type AssetfinderTool struct{}

func (t *AssetfinderTool) Name() string {
	return "assetfinder"
}

func (t *AssetfinderTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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
