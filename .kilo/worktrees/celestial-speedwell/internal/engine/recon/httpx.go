package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

type HTTPXTool struct{}

type httpxOutput struct {
	URL        string `json:"url"`
	StatusCode int    `json:"statuscode"`
	Title      string `json:"title"`
	Server     string `json:"server"`
	IP         string `json:"ip"`
}

func (t *HTTPXTool) Name() string {
	return "httpx"
}

func (t *HTTPXTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	args := []string{"-silent", "-json", "-c", fmt.Sprintf("%d", threads)}

	// Optimization: Pass targets via stdin instead of arguments to avoid ARG_MAX OS limits
	input := strings.Join(targets, "\n")
	output, err := RunCommandWithInput(ctx, []byte(input), "httpx", args...)
	if err != nil {
		if strings.Contains(err.Error(), "No such option") || strings.Contains(err.Error(), "invalid option") {
			return nil, fmt.Errorf("httpx version conflict: projectdiscovery httpx required, but another version was found in PATH")
		}
		return nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	events := []Event{}
	lines := strings.Split(string(output), "\n")
	jsonParsed := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var out httpxOutput
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			continue
		}
		jsonParsed++
		props := map[string]string{
			"status_code": fmt.Sprintf("%d", out.StatusCode),
			"title":       out.Title,
			"server":      out.Server,
			"ip":          out.IP,
		}
		events = append(events, NewEvent(out.URL, t.Name(), "service", props))
	}

	if jsonParsed == 0 && len(lines) > 0 && strings.TrimSpace(string(output)) != "" {
		return nil, fmt.Errorf("httpx failed to produce JSON output; check if projectdiscovery httpx is installed")
	}

	return events, nil
}
