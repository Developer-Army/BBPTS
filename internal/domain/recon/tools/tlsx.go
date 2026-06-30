package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
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

	args := []string{"-silent", "-san", "-cn", "-json", "-concurrency", fmt.Sprintf("%d", threads)}

	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "tlsx", args...)
	if err != nil {
		return nil, fmt.Errorf("tlsx execution failed: %w", err)
	}

	events := make([]recon.Event, 0)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		domain := extractTLSXDomain(line)
		if domain == "" {
			continue
		}

		events = append(events, recon.NewEvent(domain, t.Name(), "discovery", map[string]string{
			"source_target": strings.Join(targets, ","),
			"raw_output":    line,
		}))

		if strings.Contains(line, "\"expired\":true") {
			events = append(events, recon.NewEventWithSeverity(domain, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Expired TLS Certificate",
				"severity":    "high",
				"description": fmt.Sprintf("TLS certificate for %s has expired.", domain),
				"raw_output":  line,
			}, "high"))
		}

		if strings.Contains(line, "\"self_signed\":true") {
			events = append(events, recon.NewEventWithSeverity(domain, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Self-Signed TLS Certificate",
				"severity":    "medium",
				"description": fmt.Sprintf("TLS certificate for %s is self-signed.", domain),
				"raw_output":  line,
			}, "medium"))
		}

		if strings.Contains(line, "\"mismatched\":true") {
			events = append(events, recon.NewEventWithSeverity(domain, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "TLS Certificate SAN Mismatch",
				"severity":    "high",
				"description": fmt.Sprintf("TLS certificate for %s has a Subject Alternative Name mismatch.", domain),
				"raw_output":  line,
			}, "high"))
		}
	}

	return events, nil
}

func extractTLSXDomain(line string) string {
	if strings.HasPrefix(line, "{") {
		for _, part := range []string{"\"host\":", "\"input\":\"", "\"cn\":"} {
			idx := strings.Index(line, part)
			if idx < 0 {
				continue
			}
			val := line[idx+len(part):]
			val = strings.Trim(val, "\" ")
			if endIdx := strings.IndexAny(val, "\",\n"); endIdx > 0 {
				val = val[:endIdx]
			}
			val = strings.TrimSpace(val)
			if val != "" {
				return val
			}
		}
	}
	parts := strings.Fields(line)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return ""
}

var _ recon.Tool = (*TLSXTool)(nil)
