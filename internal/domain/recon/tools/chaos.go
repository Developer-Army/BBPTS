package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"os"
	"strings"
)

type ChaosTool struct{}

func (t *ChaosTool) Name() string {
	return "chaos"
}

func (t *ChaosTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	tmpFile, err := os.CreateTemp("", "chaos-targets-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file for chaos: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(strings.Join(targets, "\n")); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("failed to write targets to temp file: %w", err)
	}
	tmpFile.Close()

	args := []string{"-silent", "-dL", tmpFile.Name()}
	key := strings.TrimSpace(scanCtx.APIKeys["chaos"])
	if key == "" {

		return nil, nil
	}
	args = append(args, "-key", key)

	qg := scanCtx.QuotaGuard
	if qg != nil {
		qg.Increment("chaos")
	}

	lines, err := RunCommandLines(ctx, "chaos", args...)
	if err != nil {
		return nil, fmt.Errorf("chaos execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"enrichment": value}
	}), nil
}
