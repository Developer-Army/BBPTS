package services

import (
	"context"
	"fmt"
)

type HakrawlerTool struct{}

func (t *HakrawlerTool) Name() string {
	return "hakrawler"
}

func (t *HakrawlerTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var allLines []string
	for _, target := range targets {
		args := []string{"-d", "2", "-t", fmt.Sprintf("%d", threads), "-u", "-subs"}
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
