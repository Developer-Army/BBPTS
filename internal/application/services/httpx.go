package services

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
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

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())

	args := []string{
		"-silent", "-json",
		"-t", fmt.Sprintf("%d", threads),
		"-timeout", "10",
		"-retries", "1",
		"-fc", "404,500,502,503",
	}

	if _, err := os.Stat("configs/resolvers.txt"); err == nil {
		args = append(args, "-resolvers", "configs/resolvers.txt")
	}

	if rateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit))
	}

	headers := HeadersFromCtx(ctx)
	for k, v := range headers {
		args = append(args, "-header", fmt.Sprintf("%s: %s", k, v))
	}

	// Optimization: Pass targets via stdin instead of arguments to avoid ARG_MAX OS limits
	input := strings.Join(targets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "httpx", args...)
	if err != nil {
		if strings.Contains(err.Error(), "No such option") || strings.Contains(err.Error(), "invalid option") {
			return nil, fmt.Errorf("httpx version conflict: projectdiscovery httpx required, but another version was found in PATH")
		}
		return nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	events := []Event{}
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

	if jsonParsed == 0 && len(lines) > 0 {
		return nil, fmt.Errorf("httpx failed to produce JSON output; check if projectdiscovery httpx is installed")
	}

	return events, nil
}
