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

type GithubPrivateReposTool struct{}

func (t *GithubPrivateReposTool) Name() string { return "github_private_repos" }

var privSecretRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(?:secret|client[_-]?secret)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*["']([^"']{6,})["']`),
	regexp.MustCompile(`(?i)(?:token|access[_-]?token)\s*[:=]\s*["']([^"']{8,})["']`),
	regexp.MustCompile(`(?i)(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["']?(AKIA[0-9A-Z]{16})["']?`),
	regexp.MustCompile(`(?i)(?:aws[_-]?secret)\s*[:=]\s*["']([^"']{40})["']`),
	regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----`),
	regexp.MustCompile(`(?i)(?:DATABASE_URL|REDIS_URL|MONGODB_URI)\s*[:=]\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)(?:STRIPE[_-]?SECRET|SENDGRID[_-]?KEY|TWILIO[_-]?TOKEN)\s*[:=]\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)(?:JWT[_-]?SECRET|SIGNING[_-]?KEY)\s*[:=]\s*["']([^"']{8,})["']`),
}

var privEndpointRe = []*regexp.Regexp{
	regexp.MustCompile(`https?://[a-zA-Z0-9._-]+(?:\.internal|\.local|\.staging|\.dev)\.[a-zA-Z0-9._-]+`),
	regexp.MustCompile(`https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::[0-9]+)?`),
	regexp.MustCompile(`/api/(?:internal|admin|v[0-9]+)/[a-zA-Z0-9._/-]+`),
}

func (t *GithubPrivateReposTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	apiKey := scanCtx.APIKeys["github"]
	if apiKey == "" {
		slog.Debug("github_private_repos: no GitHub token, skipping")
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
			evts, _ := t.scan(ctx, apiKey, tgt)
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *GithubPrivateReposTool) scan(ctx context.Context, apiKey, orgOrRepo string) ([]recon.Event, error) {
	events := []recon.Event{}

	repos := t.listPrivateRepos(ctx, apiKey, orgOrRepo)

	for _, repo := range repos {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		events = append(events, t.scanRepo(ctx, apiKey, repo)...)
	}

	return events, nil
}

func (t *GithubPrivateReposTool) listPrivateRepos(ctx context.Context, apiKey, orgOrRepo string) []string {
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

		apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&page=%d&type=private", orgOrRepo, page)
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

		if resp.StatusCode == 403 || resp.StatusCode == 404 {
			break
		}

		var list []struct {
			FullName string `json:"full_name"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			break
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

func (t *GithubPrivateReposTool) scanRepo(ctx context.Context, apiKey, repo string) []recon.Event {
	events := []recon.Event{}

	sensitivePaths := []string{
		".env", ".env.local", ".env.production", ".env.staging",
		"config.json", "config.yml", "config.yaml", "settings.json",
		"docker-compose.yml", "Dockerfile",
		".htpasswd", "credentials.json", "service-account.json",
		"key.json", "private-key.pem", ".npmrc", ".pypirc",
		"wp-config.php", "application.properties", "secrets.yml",
		"terraform.tfvars", "vault.yml",
	}

	client := NewSafeHTTPClient(12 * time.Second)

	for _, path := range sensitivePaths {
		select {
		case <-ctx.Done():
			return events
		default:
		}

		content := t.fetchFile(ctx, apiKey, client, repo, path)
		if content == "" {
			continue
		}

		events = append(events, t.analyzeContent(repo, path, content)...)
	}

	events = append(events, t.scanTree(ctx, apiKey, repo)...)

	return events
}

func (t *GithubPrivateReposTool) fetchFile(ctx context.Context, apiKey string, client *http.Client, repo, path string) string {
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
	if err != nil || resp.StatusCode != 200 {
		if resp != nil {
			resp.Body.Close()
		}
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
		Size     int    `json:"size"`
	}
	if err := json.Unmarshal(body, &fc); err != nil {
		return ""
	}

	if fc.Size > 1024*1024 {
		return ""
	}

	if fc.Encoding == "base64" {
		if decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(fc.Content, "\n", "")); err == nil {
			return string(decoded)
		}
	}

	return fc.Content
}

func (t *GithubPrivateReposTool) analyzeContent(repo, filePath, content string) []recon.Event {
	events := []recon.Event{}

	seen := map[string]bool{}

	for _, p := range privSecretRe {
		for _, m := range p.FindAllStringSubmatch(content, -1) {
			val := ""
			if len(m) > 1 {
				val = m[1]
				if len(val) > 80 {
					val = val[:80] + "..."
				}
			}
			if seen[val] {
				continue
			}
			seen[val] = true

			events = append(events, recon.NewEvent(repo, t.Name(), "secret_exposed", map[string]string{
				"secret_type":  extractSecretType(m[0]),
				"secret_value": val,
				"file":         filePath,
				"severity":     classifySecretSeverity(m[0]),
				"scan_type":    "github_private_repos",
			}))
		}
	}

	for _, p := range privEndpointRe {
		for _, m := range p.FindAllString(content, -1) {
			if seen[m] {
				continue
			}
			seen[m] = true
			events = append(events, recon.NewEvent(m, t.Name(), "api_endpoint", map[string]string{
				"url":       m,
				"file":      filePath,
				"scan_type": "github_private_repos",
			}))
		}
	}

	return events
}

func (t *GithubPrivateReposTool) scanTree(ctx context.Context, apiKey, repo string) []recon.Event {
	events := []recon.Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/git/trees/HEAD?recursive=1", repo)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}

	var tree struct {
		Tree []struct {
			Path string `json:"path"`
			Type string `json:"type"`
		} `json:"tree"`
	}
	if err := json.Unmarshal(body, &tree); err != nil {
		return nil
	}

	sensitive := []string{".env", "config.json", "secret", "key", "token", "credential", "password", ".htpasswd"}
	scanLimit := 20
	if recon.LowResourceFromCtx(ctx) {
		scanLimit = 5
	}

	count := 0
	for _, item := range tree.Tree {
		if item.Type != "blob" {
			continue
		}
		lower := strings.ToLower(item.Path)
		isSensitive := false
		for _, s := range sensitive {
			if strings.Contains(lower, s) {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			count++
			if count > scanLimit {
				break
			}

			content := t.fetchFile(ctx, apiKey, client, repo, item.Path)
			if content != "" {
				events = append(events, t.analyzeContent(repo, item.Path, content)...)
			}
		}
	}

	return events
}
