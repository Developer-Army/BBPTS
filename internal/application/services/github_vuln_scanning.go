package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type GithubVulnScanningTool struct{}

func (t *GithubVulnScanningTool) Name() string { return "github_vuln_scanning" }

func (t *GithubVulnScanningTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	apiKey := GetAPIKey(ctx, "github")
	if apiKey == "" {
		slog.Debug("github_vuln_scanning: no GitHub token, skipping")
		return nil, nil
	}

	maxThreads := threads
	if LowResourceFromCtx(ctx) {
		if maxThreads > 1 {
			maxThreads = 1
		}
	} else if maxThreads > 3 {
		maxThreads = 3
	}

	events := []Event{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxThreads)

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		wg.Add(1)
		go func(tgt string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			evts, _ := t.scan(ctx, apiKey, tgt)
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *GithubVulnScanningTool) scan(ctx context.Context, apiKey, orgOrRepo string) ([]Event, error) {
	events := []Event{}

	repos := t.expandRepos(ctx, apiKey, orgOrRepo)

	for _, repo := range repos {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		events = append(events, t.scanDependabot(ctx, apiKey, repo)...)
		events = append(events, t.scanCodeQL(ctx, apiKey, repo)...)
		events = append(events, t.scanSecretScanning(ctx, apiKey, repo)...)
	}

	return events, nil
}

func (t *GithubVulnScanningTool) expandRepos(ctx context.Context, apiKey, orgOrRepo string) []string {
	if strings.Contains(orgOrRepo, "/") {
		return []string{orgOrRepo}
	}

	repos := []string{}
	client := NewSafeHTTPClient(12 * time.Second)
	page := 1

	for {
		select {
		case <-ctx.Done():
			return repos
		default:
		}

		apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&page=%d", orgOrRepo, page)
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return repos
		}
		req.Header.Set("Authorization", "token "+apiKey)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		for k, v := range HeadersFromCtx(ctx) {
			req.Header.Set(k, v)
		}

		if qg := GetQuotaGuard(ctx); qg != nil {
			qg.Increment("github")
		}

		resp, err := client.Do(req)
		if err != nil {
			return repos
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if err != nil {
			return repos
		}

		if resp.StatusCode == 404 {
			return []string{orgOrRepo}
		}

		var list []struct {
			FullName string `json:"full_name"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return repos
		}

		for _, r := range list {
			repos = append(repos, r.FullName)
		}

		if len(list) < 100 {
			break
		}
		page++
	}

	return repos
}

func (t *GithubVulnScanningTool) scanDependabot(ctx context.Context, apiKey, repo string) []Event {
	events := []Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/dependabot/alerts?per_page=100&state=open", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	for k, v := range HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}

	if qg := GetQuotaGuard(ctx); qg != nil {
		qg.Increment("github")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 404 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}

	var alerts []struct {
		State string `json:"state"`
		Severity string `json:"severity"`
		SecurityAdvisory struct {
			Summary  string `json:"summary"`
			Severity string `json:"severity"`
		} `json:"security_advisory"`
	}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil
	}

	for _, a := range alerts {
		if a.State != "open" {
			continue
		}
		sev := a.Severity
		if sev == "" {
			sev = a.SecurityAdvisory.Severity
		}
		if sev == "" {
			sev = "unknown"
		}
		events = append(events, NewEvent(repo, t.Name(), "vulnerability", map[string]string{
			"source":      "dependabot",
			"severity":    sev,
			"description": a.SecurityAdvisory.Summary,
			"scan_type":   "github_vuln_scanning",
		}))
	}

	return events
}

func (t *GithubVulnScanningTool) scanCodeQL(ctx context.Context, apiKey, repo string) []Event {
	events := []Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/code-scanning/alerts?per_page=100&state=open", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	for k, v := range HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}

	if qg := GetQuotaGuard(ctx); qg != nil {
		qg.Increment("github")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 404 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}

	var alerts []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Message  struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifact_location"`
				Region struct {
					StartLine int `json:"start_line"`
				} `json:"region"`
			} `json:"physical_location"`
		} `json:"location"`
	}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil
	}

	for _, a := range alerts {
		events = append(events, NewEvent(repo, t.Name(), "vulnerability", map[string]string{
			"source":      "codeql",
			"rule_id":     a.RuleID,
			"severity":    strings.ToLower(a.Severity),
			"description": a.Message.Text,
			"file":        a.Location.PhysicalLocation.ArtifactLocation.URI,
			"line":        fmt.Sprintf("%d", a.Location.PhysicalLocation.Region.StartLine),
			"scan_type":   "github_vuln_scanning",
		}))
	}

	return events
}

func (t *GithubVulnScanningTool) scanSecretScanning(ctx context.Context, apiKey, repo string) []Event {
	events := []Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/secret-scanning/alerts?per_page=100&state=open", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	for k, v := range HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}

	if qg := GetQuotaGuard(ctx); qg != nil {
		qg.Increment("github")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode == 403 || resp.StatusCode == 404 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}

	var alerts []struct {
		State  string `json:"state"`
		Pattern struct {
			SecretType string `json:"secret_type"`
		} `json:"pattern"`
	}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil
	}

	for _, a := range alerts {
		if a.State != "open" {
			continue
		}
		sev := "high"
		if strings.Contains(a.Pattern.SecretType, "token") || strings.Contains(a.Pattern.SecretType, "key") {
			sev = "critical"
		}
		events = append(events, NewEvent(repo, t.Name(), "secret_exposed", map[string]string{
			"source":      "secret_scanning",
			"secret_type": a.Pattern.SecretType,
			"severity":    sev,
			"scan_type":   "github_vuln_scanning",
		}))
	}

	return events
}
