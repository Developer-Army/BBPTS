package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type GithubVulnScanningTool struct{}

func (t *GithubVulnScanningTool) Name() string { return "github_vuln_scanning" }

func (t *GithubVulnScanningTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	apiKey := scanCtx.APIKeys["github"]
	if apiKey == "" {
		slog.Debug("github_vuln_scanning: no GitHub token, skipping")
		return nil, nil
	}

	maxThreads := threads
	if scanCtx.LowResource {
		if maxThreads > 1 {
			maxThreads = 1
		}
	} else if maxThreads > 3 {
		maxThreads = 3
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 3
	}

	pool := NewWorkerPool(maxThreads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}
		return t.scan(ctx, apiKey, target)
	})
}

func (t *GithubVulnScanningTool) scan(ctx context.Context, apiKey, orgOrRepo string) ([]recon.Event, error) {
	events := []recon.Event{}

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
		for k, v := range recon.HeadersFromCtx(ctx) {
			req.Header.Set(k, v)
		}

		if qg := recon.GetQuotaGuard(ctx); qg != nil {
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

func (t *GithubVulnScanningTool) scanDependabot(ctx context.Context, apiKey, repo string) []recon.Event {
	events := []recon.Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/dependabot/alerts?per_page=100&state=open", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	for k, v := range recon.HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}

	if qg := recon.GetQuotaGuard(ctx); qg != nil {
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
		State            string `json:"state"`
		Severity         string `json:"severity"`
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
		events = append(events, recon.NewEvent(repo, t.Name(), "vulnerability", map[string]string{
			"source":      "dependabot",
			"severity":    sev,
			"description": a.SecurityAdvisory.Summary,
			"scan_type":   "github_vuln_scanning",
		}))
	}

	return events
}

func (t *GithubVulnScanningTool) scanCodeQL(ctx context.Context, apiKey, repo string) []recon.Event {
	events := []recon.Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/code-scanning/alerts?per_page=100&state=open", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	for k, v := range recon.HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}

	if qg := recon.GetQuotaGuard(ctx); qg != nil {
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
		Rule struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		} `json:"rule"`
		MostRecentInstance struct {
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Location struct {
				Path      string `json:"path"`
				StartLine int    `json:"start_line"`
			} `json:"location"`
		} `json:"most_recent_instance"`
	}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil
	}

	for _, a := range alerts {
		events = append(events, recon.NewEvent(repo, t.Name(), "vulnerability", map[string]string{
			"source":      "codeql",
			"rule_id":     a.Rule.ID,
			"severity":    strings.ToLower(a.Rule.Severity),
			"description": a.MostRecentInstance.Message.Text,
			"file":        a.MostRecentInstance.Location.Path,
			"line":        fmt.Sprintf("%d", a.MostRecentInstance.Location.StartLine),
			"scan_type":   "github_vuln_scanning",
		}))
	}

	return events
}

func (t *GithubVulnScanningTool) scanSecretScanning(ctx context.Context, apiKey, repo string) []recon.Event {
	events := []recon.Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/secret-scanning/alerts?per_page=100&state=open", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "token "+apiKey)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	for k, v := range recon.HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}

	if qg := recon.GetQuotaGuard(ctx); qg != nil {
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
		State      string `json:"state"`
		SecretType string `json:"secret_type"`
	}
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil
	}

	for _, a := range alerts {
		if a.State != "open" {
			continue
		}
		sev := "high"
		if strings.Contains(a.SecretType, "token") || strings.Contains(a.SecretType, "key") {
			sev = "critical"
		}
		events = append(events, recon.NewEvent(repo, t.Name(), "secret_exposed", map[string]string{
			"source":      "secret_scanning",
			"secret_type": a.SecretType,
			"severity":    sev,
			"scan_type":   "github_vuln_scanning",
		}))
	}

	return events
}
