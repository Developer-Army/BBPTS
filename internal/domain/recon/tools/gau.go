package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"strings"
)

type GauTool struct{}

func (t *GauTool) Name() string {
	return "gau"
}

func (t *GauTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"--threads", fmt.Sprintf("%d", threads), "--subs"}
	headers := scanCtx.Headers
	for k, v := range headers {
		args = append(args, "--header", fmt.Sprintf("%s: %s", k, v))
	}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "gau", args...)
	if err != nil {
		return nil, fmt.Errorf("gau execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"history_url": value}
	}), nil
}
