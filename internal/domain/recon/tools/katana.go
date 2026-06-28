package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"strings"
)

type KatanaTool struct{}

func (t *KatanaTool) Name() string {
	return "katana"
}

func (t *KatanaTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-list", "-", "-c", fmt.Sprintf("%d", threads)}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}

	headers := scanCtx.Headers
	for k, v := range headers {
		args = append(args, "-header", fmt.Sprintf("%s: %s", k, v))
	}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "katana", args...)
	if err != nil {
		return nil, fmt.Errorf("katana execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"endpoint": value}
	}), nil
}
