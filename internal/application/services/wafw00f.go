package services

import (
	"context"
	"log/slog"
	"strings"
)

type Wafw00fTool struct{}

func (t *Wafw00fTool) Name() string {
	return "wafw00f"
}

func (t *Wafw00fTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := make([]Event, 0)

	for _, target := range targets {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Ensure target has a scheme
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		// Run wafw00f
		args := []string{"-a", target}
		lines, err := RunCommandLines(ctx, "wafw00f", args...)
		if err != nil {
			slog.Debug("wafw00f execution warning", "target", target, "error", err)
			continue
		}

		wafDetected := false
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
						wafDetected = true
					}
				}
			}
		}

		if wafDetected {
			slog.Debug("WAF detected", "target", target)
		}
	}

	return events, nil
}
