package services

import (
	"context"
	"fmt"
	"strings"
)

type FindomainTool struct{}

func (t *FindomainTool) Name() string {
	return "findomain"
}

func (t *FindomainTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := make([]Event, 0)

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		// Run findomain
		args := []string{"-t", target, "--quiet"}
		lines, err := RunCommandLines(ctx, "findomain", args...)
		if err != nil {
			return nil, fmt.Errorf("findomain execution failed for %s: %w", target, err)
		}

		for _, line := range lines {
			domain := strings.TrimSpace(line)
			if domain == "" || strings.HasPrefix(domain, "Findomain") || strings.Contains(domain, "An unique") {
				continue
			}

			props := map[string]string{
				"source_domain": target,
			}
			events = append(events, NewEvent(domain, t.Name(), "subdomain", props))
		}
	}

	return events, nil
}
