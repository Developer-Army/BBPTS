package services

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

type RetryConfig = tools.RetryConfig

func DefaultRetryConfig() RetryConfig {
	return tools.DefaultRetryConfig()
}

func ToolRetryConfig() RetryConfig {
	return tools.ToolRetryConfig()
}

type RetryableFunc = tools.RetryableFunc

func ExecuteWithRetry(ctx context.Context, cfg RetryConfig, fn RetryableFunc) error {
	return tools.ExecuteWithRetry(ctx, cfg, fn)
}

func RunToolWithRetry(ctx context.Context, tool Tool, scanCtx *recon.ScanContext, targets []string, threads int, cfg RetryConfig) ([]Event, error) {
	var result []Event
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		events, err := tool.Run(ctx, scanCtx, targets, threads)
		if err != nil {

			if ctx.Err() != nil {
				return false, err
			}
			return true, err
		}
		result = events
		return false, nil
	})
	return result, err
}

func RunCommandWithRetry(ctx context.Context, cfg RetryConfig, name string, args ...string) ([]string, error) {
	var result []string
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		lines, err := tools.RunCommandStreamWithInput(ctx, nil, name, args...)
		if err != nil {
			if ctx.Err() != nil {
				return false, err
			}
			return true, err
		}
		result = lines
		return false, nil
	})
	return result, err
}
