package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"os"
	"strings"
)

type PurednsTool struct{}

func (t *PurednsTool) Name() string {
	return "puredns"
}

func (t *PurednsTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

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
