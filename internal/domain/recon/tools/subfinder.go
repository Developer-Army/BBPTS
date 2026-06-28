package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

type SubfinderTool struct{}

func (t *SubfinderTool) Name() string {
	return "subfinder"
}

func (t *SubfinderTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())

	args := []string{
		"-silent",
		"-t", fmt.Sprintf("%d", threads),
		"-timeout", "20",
	}

	// Generate provider config from BBPTS API keys
	keys := recon.APIKeysFromCtx(ctx)
	if providerConfigPath, err := config.WriteSubfinderProviderConfig(keys); err == nil && providerConfigPath != "" {
		args = append(args, "-pc", providerConfigPath)
		defer os.Remove(providerConfigPath)
	}

	if _, err := os.Stat("configs/resolvers.txt"); err == nil {
		args = append(args, "-r", "configs/resolvers.txt")
	}

	if rateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", rateLimit))
	}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "subfinder", args...)
	if err != nil {
		return nil, fmt.Errorf("subfinder execution failed: %w", err)
	}

	return NewEventsFromLinesFunc(lines, t.Name(), func(value string) map[string]string {
		return map[string]string{"source_target": value}
	}), nil
}
