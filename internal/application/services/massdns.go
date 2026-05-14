package services

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

type MassdnsTool struct{}

func (t *MassdnsTool) Name() string {
	return "massdns"
}

func (t *MassdnsTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
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

		// Build a temporary list file for massdns
		args := []string{"-r", "/etc/resolv.conf", "-t", "A", "-o", "S"}

		// Run massdns with stdin
		cmd := fmt.Sprintf("echo '%s' | massdns %s", target, strings.Join(args, " "))
		lines, err := RunCommandLines(ctx, "bash", "-c", cmd)
		if err != nil {
			slog.Debug("massdns execution warning", "target", target, "error", err)
			continue
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, ";") {
				continue
			}

			// Parse massdns output: domain. A ip
			parts := strings.Fields(line)
			if len(parts) >= 3 && parts[1] == "A" {
				domain := strings.TrimSuffix(parts[0], ".")
				ip := parts[2]

				props := map[string]string{
					"ip":     ip,
					"record": "A",
				}
				events = append(events, NewEvent(domain, t.Name(), "dns-resolution", props))
			}
		}
	}

	return events, nil
}
