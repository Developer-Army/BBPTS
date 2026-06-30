package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"os"
	"strings"
)

type DNSXTool struct{}

func (t *DNSXTool) Name() string {
	return "dnsx"
}

func (t *DNSXTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-t", fmt.Sprintf("%d", threads)}
	if _, err := os.Stat("configs/resolvers.txt"); err == nil {
		args = append(args, "-r", "configs/resolvers.txt")
	}
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "dnsx", args...)
	if err != nil {
		return nil, fmt.Errorf("dnsx execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"dns_entry": value}
	}), nil
}
