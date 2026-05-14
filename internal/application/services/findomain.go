package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type FindomainTool struct{}

type findomainOutput struct {
	Domain string `json:"domain"`
	Host   string `json:"host"`
}

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
		args := []string{"-t", target, "-json"}
		lines, err := RunCommandLines(ctx, "findomain", args...)
		if err != nil {
			return nil, fmt.Errorf("findomain execution failed for %s: %w", target, err)
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var out findomainOutput
			if err := json.Unmarshal([]byte(line), &out); err != nil {
				continue
			}

			domain := out.Host
			if domain == "" {
				domain = out.Domain
			}
			if domain == "" {
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
