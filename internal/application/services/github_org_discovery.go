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

type GithubOrgDiscoveryTool struct{}

func (t *GithubOrgDiscoveryTool) Name() string { return "github_org_discovery" }

func (t *GithubOrgDiscoveryTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	apiKey := GetAPIKey(ctx, "github")
	if apiKey == "" {
		slog.Debug("github_org_discovery: no GitHub token, skipping")
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
			evts, _ := t.discover(ctx, apiKey, tgt)
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *GithubOrgDiscoveryTool) discover(ctx context.Context, apiKey, orgOrDomain string) ([]Event, error) {
	events := []Event{}

	orgName := orgOrDomain
	if strings.Contains(orgOrDomain, ".") {
		orgName = strings.Split(orgOrDomain, ".")[0]
	}

	client := NewSafeHTTPClient(12 * time.Second)

	orgInfo := t.fetchOrg(ctx, apiKey, client, orgName)
	if orgInfo != nil {
		events = append(events, NewEvent(orgName, t.Name(), "discovery", map[string]string{
			"org_name":   orgInfo["login"],
			"name":       orgInfo["name"],
			"description": orgInfo["description"],
			"email":      orgInfo["email"],
			"blog":       orgInfo["blog"],
			"location":   orgInfo["location"],
			"repos":      orgInfo["public_repos"],
			"scan_type":  "github_org_discovery",
		}))

		if blog := orgInfo["blog"]; blog != "" {
			events = append(events, NewEvent(blog, t.Name(), "discovery", map[string]string{
				"type": "org_website", "org": orgName, "scan_type": "github_org_discovery",
			}))
			if domain := extractDomain(blog); domain != "" {
				events = append(events, NewEvent(domain, t.Name(), "subdomain", map[string]string{
					"source": "org_website", "scan_type": "github_org_discovery",
				}))
			}
		}

		if email := orgInfo["email"]; email != "" {
			events = append(events, NewEvent(email, t.Name(), "discovery", map[string]string{
				"type": "org_email", "org": orgName, "scan_type": "github_org_discovery",
			}))
		}
	}

	events = append(events, t.listRepos(ctx, apiKey, orgName)...)
	events = append(events, t.listMembers(ctx, apiKey, orgName)...)
	events = append(events, t.scanWebhooks(ctx, apiKey, orgName)...)

	return events, nil
}

func (t *GithubOrgDiscoveryTool) fetchOrg(ctx context.Context, apiKey string, client *http.Client, org string) map[string]string {
	apiURL := fmt.Sprintf("https://api.github.com/orgs/%s", org)
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil
	}

	var data struct {
		Name        string `json:"name"`
		Login       string `json:"login"`
		Description string `json:"description"`
		Email       string `json:"email"`
		Blog        string `json:"blog"`
		Location    string `json:"location"`
		PublicRepos int    `json:"public_repos"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	return map[string]string{
		"name":        data.Name,
		"login":       data.Login,
		"description": data.Description,
		"email":       data.Email,
		"blog":        data.Blog,
		"location":    data.Location,
		"public_repos": fmt.Sprintf("%d", data.PublicRepos),
	}
}

func (t *GithubOrgDiscoveryTool) listRepos(ctx context.Context, apiKey, org string) []Event {
	events := []Event{}
	client := NewSafeHTTPClient(12 * time.Second)
	page := 1

	for {
		select {
		case <-ctx.Done():
			return events
		default:
		}

		apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/repos?per_page=100&page=%d&type=public", org, page)
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return events
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
			return events
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if err != nil {
			return events
		}

		var list []struct {
			Name        string   `json:"name"`
			FullName    string   `json:"full_name"`
			Description string   `json:"description"`
			Language    string   `json:"language"`
			Topics      []string `json:"topics"`
			Homepage    string   `json:"homepage"`
			Fork        bool     `json:"fork"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return events
		}

		for _, r := range list {
			events = append(events, NewEvent(r.FullName, t.Name(), "discovery", map[string]string{
				"repo":        r.Name,
				"description": r.Description,
				"language":    r.Language,
				"topics":      strings.Join(r.Topics, ","),
				"homepage":    r.Homepage,
				"is_fork":     fmt.Sprintf("%t", r.Fork),
				"org":         org,
				"scan_type":   "github_org_discovery",
			}))

			if r.Homepage != "" {
				events = append(events, NewEvent(r.Homepage, t.Name(), "discovery", map[string]string{
					"type": "repo_homepage", "repo": r.FullName, "scan_type": "github_org_discovery",
				}))
				if domain := extractDomain(r.Homepage); domain != "" {
					events = append(events, NewEvent(domain, t.Name(), "subdomain", map[string]string{
						"source": "repo_homepage", "repo": r.FullName, "scan_type": "github_org_discovery",
					}))
				}
			}
		}

		if len(list) < 100 {
			break
		}
		page++
	}

	return events
}

func (t *GithubOrgDiscoveryTool) listMembers(ctx context.Context, apiKey, org string) []Event {
	events := []Event{}
	client := NewSafeHTTPClient(12 * time.Second)
	page := 1

	for {
		select {
		case <-ctx.Done():
			return events
		default:
		}

		apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/members?per_page=100&page=%d", org, page)
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return events
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
			return events
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()
		if err != nil {
			return events
		}

		var list []struct {
			Login string `json:"login"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return events
		}

		for _, m := range list {
			profile := fmt.Sprintf("https://github.com/%s", m.Login)
			events = append(events, NewEvent(m.Login, t.Name(), "github_account", map[string]string{
				"member_url": profile, "org": org, "scan_type": "github_org_discovery",
			}))
		}

		if len(list) < 100 {
			break
		}
		page++
	}

	return events
}

func (t *GithubOrgDiscoveryTool) scanWebhooks(ctx context.Context, apiKey, org string) []Event {
	events := []Event{}

	client := NewSafeHTTPClient(12 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/hooks?per_page=100", org)
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

	var hooks []struct {
		ID     int64  `json:"id"`
		Name   string `json:"name"`
		Events []string `json:"events"`
		Config struct {
			URL string `json:"url"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &hooks); err != nil {
		return nil
	}

	for _, h := range hooks {
		events = append(events, NewEvent(h.Config.URL, t.Name(), "discovery", map[string]string{
			"hook_id":   fmt.Sprintf("%d", h.ID),
			"hook_name": h.Name,
			"events":    strings.Join(h.Events, ","),
			"org":       org,
			"scan_type": "github_org_discovery",
		}))

		if h.Config.URL != "" {
			if domain := extractDomain(h.Config.URL); domain != "" {
				events = append(events, NewEvent(domain, t.Name(), "subdomain", map[string]string{
					"source": "webhook", "org": org, "scan_type": "github_org_discovery",
				}))
			}
		}
	}

	return events
}
