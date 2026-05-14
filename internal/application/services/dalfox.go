package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type DalfoxTool struct{}

type dalfoxOutput struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Payload   string `json:"payload"`
	Parameter string `json:"parameter"`
	Severity  string `json:"severity"`
	Evidence  string `json:"evidence"`
}

func (t *DalfoxTool) Name() string {
	return "dalfox"
}

func (t *DalfoxTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := make([]Event, 0)
	for _, target := range targets {
		args := []string{"url", target, "-silent", "-json"}
		lines, err := RunCommandLines(ctx, "dalfox", args...)
		if err != nil {
			return nil, fmt.Errorf("dalfox execution failed for %s: %w", target, err)
		}

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			var out dalfoxOutput
			if err := json.Unmarshal([]byte(line), &out); err != nil {
				continue
			}

			if out.URL == "" {
				continue
			}

			props := map[string]string{}
			if out.Severity != "" {
				props["severity"] = out.Severity
			}
			if out.Payload != "" {
				props["payload"] = out.Payload
			}
			if out.Parameter != "" {
				props["parameter"] = out.Parameter
			}
			if out.Evidence != "" {
				props["evidence"] = out.Evidence
			}

			events = append(events, NewEvent(out.URL, t.Name(), "vulnerability", props))
		}
	}

	return events, nil
}
