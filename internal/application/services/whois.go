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

		domain := target
		if idx := strings.Index(domain, "://"); idx != -1 {
			domain = domain[idx+3:]
		}
		if idx := strings.Index(domain, "/"); idx != -1 {
			domain = domain[:idx]
		}
		if idx := strings.Index(domain, ":"); idx != -1 {
			domain = domain[:idx]
		}

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
			parts := strings.SplitN(line, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.ToLower(strings.TrimSpace(parts[0]))
			val := strings.TrimSpace(parts[1])
			if val == "" {
				continue
			}

			switch key {
			case "registrar", "registrar name", "sponsoring registrar":
				registrar = val
			case "registrant", "registrant name", "registrant organization":
				registrant = val
			case "admin", "admin name", "admin organization":
				admin = val
			}
		}

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
