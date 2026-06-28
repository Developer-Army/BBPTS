package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
)

type HakrawlerTool struct{}

func (t *HakrawlerTool) Name() string {
	return "hakrawler"
}

func (t *HakrawlerTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var allLines []string
	headers := scanCtx.Headers
	for _, target := range targets {
		args := []string{"-d", "2", "-t", fmt.Sprintf("%d", threads), "-u", "-subs"}
		for k, v := range headers {
			args = append(args, "-h", fmt.Sprintf("%s: %s", k, v))
		}
		lines, err := RunCommandWithInputLines(ctx, []byte(target), "hakrawler", args...)
		if err != nil {
			return nil, fmt.Errorf("hakrawler execution failed for %s: %w", target, err)
		}
		allLines = append(allLines, lines...)
	}

	return NewEventsFromLinesFunc(allLines, t.Name(), func(value string) map[string]string {
		return map[string]string{"endpoint": value}
	}), nil
}
