package services

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

// RetryConfig configures the exponential backoff retry strategy.
type RetryConfig = tools.RetryConfig

// DefaultRetryConfig returns a production-ready retry configuration.
func DefaultRetryConfig() RetryConfig {
	return tools.DefaultRetryConfig()
}

// ToolRetryConfig returns a config tuned for external recon tool execution,
// where tools can be slow and intermittent failures are common.
func ToolRetryConfig() RetryConfig {
	return tools.ToolRetryConfig()
}

// RetryableFunc is a function that can be retried.
type RetryableFunc = tools.RetryableFunc

// ExecuteWithRetry runs fn with exponential backoff retries.
func ExecuteWithRetry(ctx context.Context, cfg RetryConfig, fn RetryableFunc) error {
	return tools.ExecuteWithRetry(ctx, cfg, fn)
}

// RunToolWithRetry is a convenience wrapper that executes a recon tool with retries
// and exponential backoff. It wraps the standard Tool.Run call.
func RunToolWithRetry(ctx context.Context, tool Tool, scanCtx *recon.ScanContext, targets []string, threads int, cfg RetryConfig) ([]Event, error) {
	var result []Event
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		events, err := tool.Run(ctx, scanCtx, targets, threads)
		if err != nil {
			// All tool errors are considered retryable unless the context is done
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

// RunCommandWithRetry wraps RunCommandStream with exponential backoff retries.
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
