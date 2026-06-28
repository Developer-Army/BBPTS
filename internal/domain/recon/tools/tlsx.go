package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"strings"
)

type TLSXTool struct{}

func (t *TLSXTool) Name() string {
	return "tlsx"
}

func (t *TLSXTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-san", "-cn", "-concurrency", fmt.Sprintf("%d", threads)}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "tlsx", args...)
	if err != nil {
		return nil, fmt.Errorf("tlsx execution failed: %w", err)
	}

	events := make([]recon.Event, 0)
	for _, line := range lines {
		domain := strings.TrimSpace(line)
		if domain != "" && !strings.Contains(domain, " ") {
			events = append(events, recon.NewEvent(domain, t.Name(), "subdomain", map[string]string{
				"source_target": strings.Join(targets, ","),
			}))
		}
	}

	return events, nil
}
