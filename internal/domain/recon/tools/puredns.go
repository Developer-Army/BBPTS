package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"os"
	"strings"
)

// PurednsTool wraps puredns for high-speed DNS resolution.
type PurednsTool struct{}

func (t *PurednsTool) Name() string {
	return "puredns"
}

func (t *PurednsTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// For resolution, we use 'resolve' mode.
	// Note: puredns usually needs a resolvers list, but we'll assume default or system setup.
	args := []string{"resolve", "--quiet", "--rate-limit", fmt.Sprintf("%d", threads*100)}
	if _, err := os.Stat("configs/resolvers.txt"); err == nil {
		args = append(args, "-r", "configs/resolvers.txt")
	}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "puredns", args...)
	if err != nil {
		return nil, fmt.Errorf("puredns execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"type": "resolved"}
	}), nil
}
