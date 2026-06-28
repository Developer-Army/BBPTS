package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// GithubDorkerTool performs passive GitHub dorking to find leaked secrets,
// config files, internal endpoints, and API references for target domains.
// Runs at Stage 0 — zero traffic to target, GitHub API only.
type GithubDorkerTool struct{}

func (t *GithubDorkerTool) Name() string {
	return "github_dorker"
}

// dorkQueries returns curated search queries for a given domain.
// Each query targets a specific class of leakage.
func dorkQueries(domain string) []struct {
	Query    string
	Category string // secret, config, endpoint, infra
} {
	d := fmt.Sprintf(`"%s"`, domain)
	return []struct {
		Query    string
		Category string
	}{
		// --- Credential / Secret Leaks ---
		{Query: d + " password", Category: "secret"},
		{Query: d + " api_key", Category: "secret"},
		{Query: d + " apikey", Category: "secret"},
		{Query: d + " secret", Category: "secret"},
		{Query: d + " token", Category: "secret"},
		{Query: d + " authorization", Category: "secret"},
		{Query: d + " AWS_ACCESS_KEY", Category: "secret"},
		{Query: d + " AWS_SECRET_KEY", Category: "secret"},
		{Query: d + " PRIVATE KEY", Category: "secret"},
		{Query: d + " client_secret", Category: "secret"},
		{Query: d + " database_url", Category: "secret"},
		{Query: d + ` "mongodb://"`, Category: "secret"},
		{Query: d + ` "postgres://"`, Category: "secret"},
		{Query: d + ` "mysql://"`, Category: "secret"},
		{Query: d + ` "redis://"`, Category: "secret"},
		{Query: d + " smtp", Category: "secret"},

		// --- Config Files ---
		{Query: d + " .env", Category: "config"},
		{Query: d + " config.yml", Category: "config"},
		{Query: d + " config.json", Category: "config"},
		{Query: d + " application.properties", Category: "config"},
		{Query: d + " wp-config.php", Category: "config"},
		{Query: d + " .htaccess", Category: "config"},
		{Query: d + " .htpasswd", Category: "config"},
		{Query: d + " docker-compose", Category: "config"},
		{Query: d + " dockerfile", Category: "config"},

		// --- Internal / Staging Endpoints ---
		{Query: d + " internal", Category: "endpoint"},
		{Query: d + " staging", Category: "endpoint"},
		{Query: d + " admin", Category: "endpoint"},

		// --- API Documentation / Routes ---
		{Query: d + " swagger.json", Category: "endpoint"},
		{Query: d + " openapi", Category: "endpoint"},
		{Query: d + " graphql", Category: "endpoint"},
	}
}

// configFilePatterns detects known config file types by path/name.
var configFilePatterns = regexp.MustCompile(
	`(?i)(?:` +
		`\.env|` +
		`config\.(?:yml|yaml|json|toml|xml|ini|properties)|` +
		`application\.properties|` +
		`wp-config\.php|` +
		`\.htaccess|` +
		`\.htpasswd|` +
		`docker-compose\.ya?ml|` +
		`Dockerfile|` +
		`\.npmrc|` +
		`\.pypirc|` +
		`credentials|` +
		`settings\.py` +
		`)`,
)

// internalEndpointPatterns detects internal/staging URLs in file content.
var internalEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)https?://[a-z0-9._-]+\.internal\.[a-z0-9._-]+`),
	regexp.MustCompile(`(?i)https?://[a-z0-9._-]+\.local\.[a-z0-9._-]+`),
	regexp.MustCompile(`(?i)https?://(?:staging|stage|dev|test|uat|preprod|sandbox)[.-][a-z0-9._-]+`),
	regexp.MustCompile(`(?i)https?://localhost[:/][^\s'"]+`),
}

// apiEndpointPatterns detects API route references in file content.
var apiEndpointPatterns = regexp.MustCompile(
	`(?i)(?:/api/v\d+[^\s'"]*|/graphql(?:/[^\s'"]*)?|/swagger[^\s'"]*|/openapi[^\s'"]*|/admin[^\s'"]*)`,
)

// dedupeKey uniquely identifies a finding to prevent duplicates across overlapping queries.
type dedupeKey struct {
	target    string
	eventType string
	value     string
}

func (t *GithubDorkerTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	apiKey := GetAPIKey(ctx, "github")
	if apiKey == "" {
		slog.Debug("GitHub API token not configured, skipping github_dorker")
		return nil, nil
	}

	var (
		events []Event
		mu     sync.Mutex
		wg     sync.WaitGroup
		seen   = make(map[dedupeKey]struct{})
	)

	// Limit concurrent domain processing
	sem := make(chan struct{}, threads)

	// Collect unique domains for org enumeration
	var uniqueDomains []string
	domainSeen := make(map[string]bool)

	for _, target := range targets {
		domain := strings.TrimSpace(target)
		if domain == "" {
			continue
		}
		domain = stripProtocol(domain)

		if !domainSeen[domain] {
			domainSeen[domain] = true
			uniqueDomains = append(uniqueDomains, domain)
		}

		wg.Add(1)
		go func(dom string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			client := NewSafeHTTPClient(20 * time.Second)
			queries := dorkQueries(dom)
			subdomainRegex := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)*%s`, regexp.QuoteMeta(dom)))

			for _, dork := range queries {
				select {
				case <-ctx.Done():
					return
				default:
				}

				items, err := searchGithubCode(ctx, client, apiKey, dork.Query)
				if err != nil {
					slog.Debug("github_dorker search failed", "query", dork.Query, "error", err)
					continue
				}

				for _, item := range items {
					select {
					case <-ctx.Done():
						return
					default:
					}

					fileContent, err := fetchRawContent(ctx, client, apiKey, item)
					if err != nil {
						continue
					}

					baseProps := map[string]string{
						"source":     "github_dorker",
						"file":       item.HTMLURL,
						"repo":       item.Repository.FullName,
						"dork_query": dork.Query,
					}

					// 1. Scan for leaked secrets
					secretMatches := recon.ScanForSecrets(fileContent)
					for _, sm := range secretMatches {
						key := dedupeKey{target: dom, eventType: "secret_exposed", value: sm.Value}
						mu.Lock()
						if _, dup := seen[key]; dup {
							mu.Unlock()
							continue
						}
						seen[key] = struct{}{}
						props := copyProps(baseProps)
						props["match_type"] = sm.PatternName
						props["severity"] = sm.Severity
						props["line"] = fmt.Sprintf("%d", sm.Line)
						events = append(events, NewEventWithSeverity(
							dom, t.Name(), "secret_exposed", props, sm.Severity,
						))
						mu.Unlock()
					}

					// 2. Detect config file exposure by file path
					if configFilePatterns.MatchString(item.Path) {
						key := dedupeKey{target: dom, eventType: "config_file", value: item.Path}
						mu.Lock()
						if _, dup := seen[key]; !dup {
							seen[key] = struct{}{}
							props := copyProps(baseProps)
							props["config_path"] = item.Path
							events = append(events, NewEvent(
								item.HTMLURL, t.Name(), "config_file", props,
							))
						}
						mu.Unlock()
					}

					// 3. Extract internal/staging endpoints
					for _, re := range internalEndpointPatterns {
						matches := re.FindAllString(fileContent, 10)
						for _, match := range matches {
							match = strings.TrimSpace(match)
							key := dedupeKey{target: dom, eventType: "internal_endpoint", value: match}
							mu.Lock()
							if _, dup := seen[key]; !dup {
								seen[key] = struct{}{}
								props := copyProps(baseProps)
								props["endpoint"] = match
								events = append(events, NewEvent(
									match, t.Name(), "internal_endpoint", props,
								))
							}
							mu.Unlock()
						}
					}

					// 4. Extract API endpoint references
					apiMatches := apiEndpointPatterns.FindAllString(fileContent, 20)
					for _, match := range apiMatches {
						match = strings.TrimSpace(match)
						key := dedupeKey{target: dom, eventType: "api_endpoint", value: match}
						mu.Lock()
						if _, dup := seen[key]; !dup {
							seen[key] = struct{}{}
							props := copyProps(baseProps)
							props["api_path"] = match
							events = append(events, NewEvent(
								match, t.Name(), "api_endpoint", props,
							))
						}
						mu.Unlock()
					}

					// 5. Extract subdomain references from content
					subMatches := subdomainRegex.FindAllString(fileContent, -1)
					for _, match := range subMatches {
						match = strings.ToLower(strings.TrimSpace(match))
						if match == "" || match == dom {
							continue
						}
						key := dedupeKey{target: dom, eventType: "subdomain", value: match}
						mu.Lock()
						if _, dup := seen[key]; !dup {
							seen[key] = struct{}{}
							props := copyProps(baseProps)
							events = append(events, NewEvent(
								match, t.Name(), "subdomain", props,
							))
						}
						mu.Unlock()
					}
				}
			}
		}(domain)
	}

	wg.Wait()

	// Phase 6: Organization member enumeration
outer:
	for _, dom := range uniqueDomains {
		select {
		case <-ctx.Done():
			break outer
		default:
		}
		orgEvents := t.enumerateOrgMembers(ctx, apiKey, dom)
		events = append(events, orgEvents...)
	}

	return events, nil
}

// enumerateOrgMembers queries the GitHub API /orgs/{org}/members to list public org members,
// then scans their personal repos for leaked secrets about the target company.
func (t *GithubDorkerTool) enumerateOrgMembers(ctx context.Context, apiKey, domain string) []Event {
	var events []Event
	orgName := extractOrgName(domain)
	if orgName == "" {
		return nil
	}

	client := NewSafeHTTPClient(20 * time.Second)
	apiURL := fmt.Sprintf("https://api.github.com/orgs/%s/members?per_page=50", orgName)

	cfg := RetryConfig{
		MaxRetries:     2,
		BaseDelay:      3 * time.Second,
		MaxDelay:       30 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.25,
	}

	var members []struct {
		Login string `json:"login"`
	}

	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		limitGithubSearch()
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "token "+apiKey)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		r, err := client.Do(req)
		if err != nil {
			return true, err
		}
		defer r.Body.Close()

		if r.StatusCode == 403 || r.StatusCode == 429 {
			return true, fmt.Errorf("rate limited: %d", r.StatusCode)
		}
		if r.StatusCode == 404 {
			return false, nil // org not found or no public members
		}
		if r.StatusCode != 200 {
			return false, fmt.Errorf("unexpected status: %d", r.StatusCode)
		}

		return false, json.NewDecoder(io.LimitReader(r.Body, 1*1024*1024)).Decode(&members)
	})

	if err != nil || len(members) == 0 {
		return nil
	}

	slog.Info("GitHub org member enumeration found members", "org", orgName, "count", len(members))

	subdomainRegex := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)*%s`, regexp.QuoteMeta(domain)))

	for _, member := range members {
		select {
		case <-ctx.Done():
			return events
		default:
		}

		memberRepos := t.fetchMemberRepos(ctx, client, apiKey, member.Login)
		for _, repo := range memberRepos {
			rawContent, err := fetchRawContent(ctx, client, apiKey, repo)
			if err != nil {
				continue
			}

			// Scan for leaked secrets referencing the target domain
			secretMatches := recon.ScanForSecrets(rawContent)
			for _, sm := range secretMatches {
				props := map[string]string{
					"source":      "github_dorker",
					"category":    "org_member_leak",
					"member":      member.Login,
					"repo":        repo.Repository.FullName,
					"file":        repo.HTMLURL,
					"match_type":  sm.PatternName,
					"severity":    sm.Severity,
					"description": fmt.Sprintf("Secret '%s' found in %s's repo %s referencing target %s", sm.PatternName, member.Login, repo.Repository.FullName, domain),
				}
				events = append(events, NewEventWithSeverity(domain, t.Name(), "secret_exposed", props, sm.Severity))
			}

			// Extract subdomains from member's repos
			subMatches := subdomainRegex.FindAllString(rawContent, -1)
			for _, match := range subMatches {
				match = strings.ToLower(strings.TrimSpace(match))
				if match == "" || match == domain {
					continue
				}
				props := map[string]string{
					"source":   "github_dorker",
					"category": "org_member_subdomain",
					"member":   member.Login,
					"repo":     repo.Repository.FullName,
				}
				events = append(events, NewEvent(match, t.Name(), "subdomain", props))
			}
		}
	}

	return events
}

func (t *GithubDorkerTool) fetchMemberRepos(ctx context.Context, client *http.Client, apiKey, username string) []githubSearchItem {
	apiURL := fmt.Sprintf("https://api.github.com/users/%s/repos?per_page=30&sort=updated", username)

	cfg := RetryConfig{
		MaxRetries:     2,
		BaseDelay:      2 * time.Second,
		MaxDelay:       10 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.2,
	}

	type repoItem struct {
		Name          string `json:"name"`
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
		HTMLURL       string `json:"html_url"`
	}

	var repos []repoItem
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		limitGithubSearch()
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "token "+apiKey)
		req.Header.Set("Accept", "application/vnd.github.v3+json")

		r, err := client.Do(req)
		if err != nil {
			return true, err
		}
		defer r.Body.Close()

		if r.StatusCode == 403 || r.StatusCode == 429 {
			return true, fmt.Errorf("rate limited: %d", r.StatusCode)
		}
		if r.StatusCode != 200 {
			return false, fmt.Errorf("unexpected status: %d", r.StatusCode)
		}

		return false, json.NewDecoder(io.LimitReader(r.Body, 2*1024*1024)).Decode(&repos)
	})

	if err != nil {
		return nil
	}

	var items []githubSearchItem
	for _, repo := range repos {
		items = append(items, githubSearchItem{
			Name:    repo.Name,
			HTMLURL: repo.HTMLURL,
			Repository: struct {
				FullName      string `json:"full_name"`
				DefaultBranch string `json:"default_branch"`
			}{
				FullName:      repo.FullName,
				DefaultBranch: repo.DefaultBranch,
			},
		})
	}
	return items
}

// extractOrgName attempts to extract a GitHub organization name from a domain.
// E.g., "example.com" → "example", "acme-corp.com" → "acme-corp".
func extractOrgName(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "www.")
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return ""
	}
	org := parts[0]
	if org == "" || len(org) < 2 {
		return ""
	}
	return org
}

// searchGithubCode queries the GitHub Code Search API with rate limiting and retry.
func searchGithubCode(ctx context.Context, client *http.Client, apiKey, query string) ([]githubSearchItem, error) {
	apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=50", url.QueryEscape(query))

	var resp *http.Response
	cfg := RetryConfig{
		MaxRetries:     3,
		BaseDelay:      5 * time.Second,
		MaxDelay:       60 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.25,
	}

	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		limitGithubSearch()

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "token "+apiKey)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
		headers := HeadersFromCtx(ctx)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		qg := GetQuotaGuard(ctx)
		if qg != nil {
			qg.Increment("github")
		}

		r, err := client.Do(req)
		if err != nil {
			return true, err
		}

		if r.StatusCode == 403 || r.StatusCode == 429 {
			r.Body.Close()
			return true, fmt.Errorf("github_dorker rate limited: %d", r.StatusCode)
		}
		if r.StatusCode != 200 {
			r.Body.Close()
			return false, fmt.Errorf("github_dorker search failed: %d", r.StatusCode)
		}

		resp = r
		return false, nil
	})

	if err != nil || resp == nil {
		return nil, err
	}
	defer resp.Body.Close()

	var searchResp githubSearchResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&searchResp); err != nil {
		return nil, fmt.Errorf("github_dorker decode error: %w", err)
	}
	return searchResp.Items, nil
}

// fetchRawContent downloads raw file content from GitHub for analysis.
func fetchRawContent(ctx context.Context, client *http.Client, apiKey string, item githubSearchItem) (string, error) {
	branch := item.Repository.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s",
		item.Repository.FullName, branch, item.Path)

	cfg := RetryConfig{
		MaxRetries:     2,
		BaseDelay:      1 * time.Second,
		MaxDelay:       5 * time.Second,
		Multiplier:     2.0,
		JitterFraction: 0.2,
	}

	var rawResp *http.Response
	err := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
		if err != nil {
			return false, err
		}
		req.Header.Set("Authorization", "token "+apiKey)
		headers := HeadersFromCtx(ctx)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		qg := GetQuotaGuard(ctx)
		if qg != nil {
			qg.Increment("github")
		}

		r, err := client.Do(req)
		if err != nil {
			return true, err
		}
		if r.StatusCode != 200 {
			r.Body.Close()
			return r.StatusCode == 429 || r.StatusCode >= 500, fmt.Errorf("raw fetch %d: %s", r.StatusCode, rawURL)
		}
		rawResp = r
		return false, nil
	})

	if err != nil || rawResp == nil {
		return "", err
	}
	defer rawResp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(rawResp.Body, 5*1024*1024))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// stripProtocol removes http(s):// and trailing paths from a domain string.
func stripProtocol(s string) string {
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if idx := strings.Index(s, "/"); idx != -1 {
		s = s[:idx]
	}
	if idx := strings.Index(s, ":"); idx != -1 {
		s = s[:idx]
	}
	return s
}

// copyProps returns a shallow copy of a string map.
func copyProps(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
