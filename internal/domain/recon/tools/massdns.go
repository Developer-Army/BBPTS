package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"log/slog"
	"strings"
)

type MassdnsTool struct{}

func (t *MassdnsTool) Name() string {
	return "massdns"
}

func (t *MassdnsTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := make([]recon.Event, 0)

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

		args := []string{"-r", "/etc/resolv.conf", "-t", "A", "-o", "S"}

		lines, err := RunCommandWithInputLines(ctx, []byte(target), "massdns", args...)
		if err != nil {
			slog.Debug("massdns execution warning", "target", target, "error", err)
			continue
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, ";") {
				continue
			}

			parts := strings.Fields(line)
			if len(parts) >= 3 && parts[1] == "A" {
				domain := strings.TrimSuffix(parts[0], ".")
				ip := parts[2]

				props := map[string]string{
					"ip":     ip,
					"record": "A",
				}
				events = append(events, recon.NewEvent(domain, t.Name(), "dns-resolution", props))
			}
		}
	}

	return events, nil
}
