package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"
)

type HTTPXTool struct{}

type httpxOutput struct {
	URL          string   `json:"url"`
	StatusCode   int      `json:"statuscode"`
	Title        string   `json:"title"`
	Server       string   `json:"server"`
	IP           string   `json:"ip"`
	Technologies []string `json:"tech"`
}

func (t *HTTPXTool) Name() string {
	return "httpx"
}

func isValidTarget(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	if strings.ContainsAny(target, " \t\r\n`'\"<>\\") {
		return false
	}
	u, err := url.Parse(target)
	if err != nil {
		return false
	}
	if u.Scheme != "" {
		if u.Scheme != "http" && u.Scheme != "https" {
			return false
		}
		if u.Host == "" {
			return false
		}
		return true
	}
	host := target
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if host == "" {
		return false
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") || strings.HasPrefix(host, "-") || strings.HasSuffix(host, "-") {
		return false
	}
	return true
}

func isParkedOrForSale(title string) bool {
	title = strings.ToLower(strings.TrimSpace(title))
	keywords := []string{
		"domain for sale",
		"domain is for sale",
		"buy this domain",
		"domain parking",
		"parked domain",
		"website for sale",
		"this website is for sale",
		"domain name is for sale",
		"domainname for sale",
		"under construction",
		"coming soon",
		"holding page",
	}
	for _, kw := range keywords {
		if strings.Contains(title, kw) {
			return true
		}
	}
	return false
}

func extractHost(target string) string {
	target = strings.TrimSpace(strings.ToLower(target))
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		host := target
		if idx := strings.Index(host, "/"); idx != -1 {
			host = host[:idx]
		}
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}
		return host
	}
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	host := u.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	return host
}

func (t *HTTPXTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var validTargets []string
	for _, target := range targets {
		if !isValidTarget(target) {
			slog.Warn("Target skipped: invalid url/domain structure", "target", target)
			continue
		}
		validTargets = append(validTargets, target)
	}

	if len(validTargets) == 0 {
		slog.Warn("All targets skipped because they are invalid")
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())

	args := []string{
		"-silent", "-tech", "-json",
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

	input := strings.Join(validTargets, "\n")
	lines, err := RunCommandWithInputLines(ctx, []byte(input), "httpx", args...)
	if err != nil {
		if strings.Contains(err.Error(), "No such option") || strings.Contains(err.Error(), "invalid option") {
			return nil, fmt.Errorf("httpx version conflict: projectdiscovery httpx required, but another version was found in PATH")
		}
		return nil, fmt.Errorf("httpx execution failed: %w", err)
	}

	events := []Event{}
	jsonParsed := 0
	foundHosts := make(map[string]bool)

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

		if isParkedOrForSale(out.Title) {
			slog.Warn("Target skipped: parked or for sale domain detected", "url", out.URL, "title", out.Title)
			continue
		}

		authRequired := "false"
		if out.StatusCode == 401 || out.StatusCode == 403 {
			authRequired = "true"
		} else {
			titleLower := strings.ToLower(out.Title)
			if strings.Contains(titleLower, "login") || strings.Contains(titleLower, "sign in") || strings.Contains(titleLower, "sign-in") || strings.Contains(titleLower, "portal") {
				authRequired = "true"
			}
		}

		props := map[string]string{
			"status_code":   fmt.Sprintf("%d", out.StatusCode),
			"title":         out.Title,
			"server":        out.Server,
			"ip":            out.IP,
			"auth_required": authRequired,
		}
		if len(out.Technologies) > 0 {
			props["technologies"] = strings.Join(out.Technologies, ",")
		}
		events = append(events, NewEvent(out.URL, t.Name(), "service", props))
		foundHosts[extractHost(out.URL)] = true
	}

	if jsonParsed == 0 && len(lines) > 0 {
		return nil, fmt.Errorf("httpx failed to produce JSON output; check if projectdiscovery httpx is installed")
	}

	for _, target := range validTargets {
		h := extractHost(target)
		if !foundHosts[h] {
			slog.Warn("Target skipped: host returned no active HTTP services", "target", target)
		}
	}

	return events, nil
}
