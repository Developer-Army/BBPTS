package services

import (
	"context"
	"log/slog"
	"strings"
)

type WhoisTool struct{}

func (t *WhoisTool) Name() string {
	return "whois"
}

func (t *WhoisTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
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

		// Extract domain from target (remove port, scheme)
		domain := target
		if strings.Contains(domain, "://") {
			domain = strings.Split(domain, "://")[1]
		}
		if strings.Contains(domain, ":") {
			domain = strings.Split(domain, ":")[0]
		}

		// Run whois
		lines, err := RunCommandLines(ctx, "whois", domain)
		if err != nil {
			slog.Debug("whois execution warning", "domain", domain, "error", err)
			continue
		}

		registrar := ""
		registrant := ""
		admin := ""

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Registrar:") {
				registrar = strings.TrimPrefix(line, "Registrar:")
				registrar = strings.TrimSpace(registrar)
			} else if strings.HasPrefix(line, "Registrant Name:") {
				registrant = strings.TrimPrefix(line, "Registrant Name:")
				registrant = strings.TrimSpace(registrant)
			} else if strings.HasPrefix(line, "Admin Name:") {
				admin = strings.TrimPrefix(line, "Admin Name:")
				admin = strings.TrimSpace(admin)
			}
		}

		// Only emit event if we found registrar info
		if registrar != "" || registrant != "" {
			props := map[string]string{
				"domain":    domain,
				"registrar": registrar,
			}
			if registrant != "" {
				props["registrant"] = registrant
			}
			if admin != "" {
				props["admin"] = admin
			}

			events = append(events, NewEvent(domain, t.Name(), "domain-info", props))
		}
	}

	return events, nil
}
