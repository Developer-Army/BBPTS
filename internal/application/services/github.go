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
)

type GithubTool struct{}

func (t *GithubTool) Name() string {
	return "github"
}

type githubSearchItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	HTMLURL    string `json:"html_url"`
	Repository struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
}

type githubSearchResponse struct {
	Items []githubSearchItem `json:"items"`
}

func (t *GithubTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	apiKey := GetAPIKey(ctx, "github")
	if apiKey == "" {
		slog.Debug("GitHub API token not configured, skipping GitHub search")
		return nil, nil
	}

	events := []Event{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, threads)

	for _, target := range targets {
		domain := strings.TrimSpace(target)
		if domain == "" {
			continue
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

			// Query GitHub search API for domain occurrences in code
			query := fmt.Sprintf(`"%s"`, dom)
			apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=50", url.QueryEscape(query))

			req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "token "+apiKey)
			req.Header.Set("Accept", "application/vnd.github.v3+json")

			client := &http.Client{Timeout: 15 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 403 {
				slog.Debug("GitHub API rate limit exceeded")
				return
			}
			if resp.StatusCode != 200 {
				return
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			var searchResp githubSearchResponse
			if err := json.Unmarshal(body, &searchResp); err != nil {
				return
			}

			// Subdomain regex for this target domain
			subdomainRegex := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9-_]+\.)*%s`, regexp.QuoteMeta(dom)))

			for _, item := range searchResp.Items {
				// Use the repository's actual default branch from the API response
				branch := item.Repository.DefaultBranch
				if branch == "" {
					branch = "main"
				}
				rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", item.Repository.FullName, branch, item.Path)

				select {
				case <-ctx.Done():
					return
				default:
				}

				rawReq, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
				if err != nil {
					continue
				}
				rawReq.Header.Set("Authorization", "token "+apiKey)

				rawResp, err := client.Do(rawReq)
				if err != nil {
					continue
				}

				if rawResp.StatusCode != 200 {
					rawResp.Body.Close()
					continue
				}

				fileBody, err := io.ReadAll(rawResp.Body)
				rawResp.Body.Close()
				if err != nil {
					continue
				}

				matches := subdomainRegex.FindAllString(string(fileBody), -1)
				for _, match := range matches {
					match = strings.ToLower(strings.TrimSpace(match))
					if match != "" {
						mu.Lock()
						events = append(events, NewEvent(match, t.Name(), "subdomain", map[string]string{
							"source": "github_code_search",
							"file":   item.HTMLURL,
						}))
						mu.Unlock()
					}
				}
			}
		}(domain)
	}

	wg.Wait()
	return events, nil
}
