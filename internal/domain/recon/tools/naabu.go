package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"strings"
)

type NaabuTool struct{}

func (t *NaabuTool) Name() string {
	return "naabu"
}

func (t *NaabuTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	defaultPorts := "20,21,22,23,25,53,67,68,80,110,119,123,137,138,139,143,161,162,389,443,445,465,514,587,631,636,993,995,1433,1434,1521,2049,3306,3389,3690,5432,5900,5984,6379,6660-6669,8000,8080,8443,8888,9000,9092,9200,9300,11211,27017,27018,27019,50000,50070,50075,61616"
	vulnerablePorts := scanCtx.Ports
	if vulnerablePorts == "" {
		vulnerablePorts = defaultPorts
	}
	args := []string{"-silent", "-c", fmt.Sprintf("%d", threads), "-p", vulnerablePorts}
	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit))
	}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "naabu", args...)
	if err != nil {
		return nil, fmt.Errorf("naabu execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"address": value}
	}), nil
}
