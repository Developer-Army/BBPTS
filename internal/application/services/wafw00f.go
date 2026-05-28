package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"golang.org/x/time/rate"
)

type Wafw00fTool struct{}

func (t *Wafw00fTool) Name() string {
	return "wafw00f"
}

func (t *Wafw00fTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		// Ensure target has a scheme
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		// Run wafw00f
		args := []string{"-a", target}
		headers := HeadersFromCtx(ctx)
		for k, v := range headers {
			args = append(args, "-H", fmt.Sprintf("%s: %s", k, v))
		}
		lines, err := RunCommandLines(ctx, "wafw00f", args...)
		if err != nil {
			slog.Debug("wafw00f execution warning", "target", target, "error", err)
			return nil, nil
		}

		var events []Event
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.Contains(strings.ToLower(line), "identified") || strings.Contains(strings.ToLower(line), "detected") {
				// Extract WAF name
				if idx := strings.LastIndex(line, ":"); idx != -1 {
					wafName := strings.TrimSpace(line[idx+1:])
					if wafName != "" && wafName != "None" {
						props := map[string]string{
							"waf_type": wafName,
						}
						events = append(events, NewEvent(target, t.Name(), "waf-detection", props))
					}
				}
			}
		}

		return events, nil
	})
}
