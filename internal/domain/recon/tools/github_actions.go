package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

type GithubActionsTool struct{}

func (t *GithubActionsTool) Name() string { return "github_actions" }

var (
	ghSecretRe = []*regexp.Regexp{
		regexp.MustCompile(`(?i)secrets\.\s*([A-Z_]+)`),
		regexp.MustCompile(`(?i)(?:GITHUB_TOKEN|GH_TOKEN|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)`),
		regexp.MustCompile(`(?i)(?:DOCKER_PASSWORD|NPM_TOKEN|PYPI_TOKEN|DEPLOY_KEY|SSH_PRIVATE_KEY)`),
		regexp.MustCompile(`(?i)(?:SLACK_WEBHOOK|DISCORD_WEBHOOK|DATABASE_URL|API_KEY|API_SECRET)`),
	}
	ghMisconfigRe = []*regexp.Regexp{
		regexp.MustCompile(`(?i)pull_request_target:`),
		regexp.MustCompile(`(?i)contents:\s*write`),
		regexp.MustCompile(`(?i)actions:\s*write`),
		regexp.MustCompile(`(?i)uses:\s*\$\{\{.*\}\}`),
		regexp.MustCompile(`(?i)run:\s*\|[\s\S]*\$\{\{`),
	}
	usesRefRe       = regexp.MustCompile(`(?i)uses:\s*[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+@([a-zA-Z0-9_.-]+)`)
	ghSupplyChainRe = []*regexp.Regexp{
		regexp.MustCompile(`(?i)curl\s+[^\|]*\|\s*(?:bash|sh)`),
		regexp.MustCompile(`(?i)wget\s+[^\|]*\|\s*(?:bash|sh)`),
		regexp.MustCompile(`(?i)npm\s+install\s+([a-zA-Z0-9@._-]+)`),
		regexp.MustCompile(`(?i)pip\s+install\s+([a-zA-Z0-9._-]+)`),
	}
)

func (t *GithubActionsTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	apiKey := scanCtx.APIKeys["github"]
	if apiKey == "" {
		slog.Debug("github_actions: no GitHub token, skipping")
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

	events := []recon.Event{}
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
			evts, _ := t.analyze(ctx, apiKey, tgt)
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *GithubActionsTool) analyze(ctx context.Context, apiKey, orgOrRepo string) ([]recon.Event, error) {
	events := []recon.Event{}

	repos := t.listRepos(ctx, apiKey, orgOrRepo)

	for _, repo := range repos {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		evts, err := t.analyzeRepo(ctx, apiKey, repo)
		if err != nil {
			continue
		}
		events = append(events, evts...)
	}

	return events, nil
}

func (t *GithubActionsTool) listRepos(ctx context.Context, apiKey, orgOrRepo string) []string {
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

func (t *GithubActionsTool) analyzeRepo(ctx context.Context, apiKey, repo string) ([]recon.Event, error) {
	events := []recon.Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/.github/workflows", repo)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var files []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &files); err != nil {
		return nil, err
	}

	for _, f := range files {
		if f.Type != "file" || (!strings.HasSuffix(f.Name, ".yml") && !strings.HasSuffix(f.Name, ".yaml")) {
			continue
		}

		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		content := t.fetchContent(ctx, apiKey, repo, f.Path)
		if content == "" {
			continue
		}

		events = append(events, t.analyzeWorkflow(content, repo, f.Name, f.Path)...)
	}

	return events, nil
}

func (t *GithubActionsTool) fetchContent(ctx context.Context, apiKey, repo, path string) string {
	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/contents/%s", repo, path)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return ""
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
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return ""
	}

	var fc struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := json.Unmarshal(body, &fc); err != nil {
		return string(body)
	}

	if fc.Encoding == "base64" {
		if decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fc.Content, "\n", "")); err == nil {
			return string(decoded)
		}
	}

	return fc.Content
}

func (t *GithubActionsTool) analyzeWorkflow(content, repo, name, path string) []recon.Event {
	events := []recon.Event{}
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		for _, p := range ghSecretRe {
			if m := p.FindAllStringSubmatch(line, -1); len(m) > 0 {
				severity := "info"
				if len(m[0]) > 10 {
					severity = "medium"
				}
				events = append(events, recon.NewEvent(repo, t.Name(), "vulnerability", map[string]string{
					"workflow":    name,
					"file":        path,
					"line":        fmt.Sprintf("%d", i+1),
					"type":        "secret_reference",
					"severity":    severity,
					"description": "Secret referenced in workflow",
					"detail":      truncateGHS(strings.Join(m[0], ""), 100),
					"scan_type":   "github_actions",
				}))
			}
		}

		for _, p := range ghMisconfigRe {
			if p.MatchString(line) {
				severity := "medium"
				desc := "Workflow misconfiguration"
				switch {
				case strings.Contains(line, "pull_request_target"):
					severity, desc = "high", "pull_request_target can execute code from forks"
				case strings.Contains(line, "contents: write") || strings.Contains(line, "actions: write"):
					severity, desc = "high", "Elevated permissions"
				case strings.Contains(line, "${{") && strings.Contains(line, "run:"):
					severity, desc = "high", "Expression injection in run step"
				}
				events = append(events, recon.NewEvent(repo, t.Name(), "vulnerability", map[string]string{
					"workflow":    name,
					"file":        path,
					"line":        fmt.Sprintf("%d", i+1),
					"type":        "misconfiguration",
					"severity":    severity,
					"description": desc,
					"detail":      strings.TrimSpace(truncateGHS(line, 100)),
					"scan_type":   "github_actions",
				}))
			}
		}

		if m := usesRefRe.FindStringSubmatch(line); len(m) > 1 {
			ref := strings.ToLower(m[1])
			isVNum := len(ref) >= 2 && ref[0] == 'v' && ref[1] >= '0' && ref[1] <= '9'
			if ref != "main" && ref != "master" && !isVNum {
				events = append(events, recon.NewEvent(repo, t.Name(), "vulnerability", map[string]string{
					"workflow":    name,
					"file":        path,
					"line":        fmt.Sprintf("%d", i+1),
					"type":        "misconfiguration",
					"severity":    "medium",
					"description": "Workflow misconfiguration",
					"detail":      strings.TrimSpace(truncateGHS(line, 100)),
					"scan_type":   "github_actions",
				}))
			}
		}

		for _, p := range ghSupplyChainRe {
			if p.MatchString(line) {
				events = append(events, recon.NewEvent(repo, t.Name(), "vulnerability", map[string]string{
					"workflow":    name,
					"file":        path,
					"line":        fmt.Sprintf("%d", i+1),
					"type":        "supply_chain",
					"severity":    "high",
					"description": "Supply chain risk",
					"detail":      strings.TrimSpace(truncateGHS(line, 100)),
					"scan_type":   "github_actions",
				}))
			}
		}
	}

	return events
}

func truncateGHS(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
