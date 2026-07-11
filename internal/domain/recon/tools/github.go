package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
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

var (
	githubSearchMu    sync.Mutex
	lastGithubSearch  time.Time
	githubSearchDelay = 2400 * time.Millisecond
)

func limitGithubSearch() {
	githubSearchMu.Lock()
	defer githubSearchMu.Unlock()
	now := time.Now()
	elapsed := now.Sub(lastGithubSearch)
	if elapsed < githubSearchDelay {
		time.Sleep(githubSearchDelay - elapsed)
	}
	lastGithubSearch = time.Now()
}

func (t *GithubTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	apiKey := scanCtx.APIKeys["github"]
	if apiKey == "" {
		slog.Debug("GitHub API token not configured, skipping GitHub search")
		return nil, nil
	}

	events := []recon.Event{}
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
			client := NewSafeHTTPClient(15 * time.Second)

			query := fmt.Sprintf("%q", dom)
			apiURL := fmt.Sprintf("https://api.github.com/search/code?q=%s&per_page=50", url.QueryEscape(query))

			var resp *http.Response
			cfg := RetryConfig{
				MaxRetries:     3,
				BaseDelay:      5 * time.Second,
				MaxDelay:       30 * time.Second,
				Multiplier:     2.0,
				JitterFraction: 0.25,
			}
			errSearch := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
				limitGithubSearch()

				req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
				if err != nil {
					return false, err
				}
				req.Header.Set("Authorization", "token "+apiKey)
				req.Header.Set("Accept", "application/vnd.github.v3+json")
				headers := scanCtx.Headers
				for k, v := range headers {
					req.Header.Set(k, v)
				}

				qg := scanCtx.QuotaGuard
				if qg != nil {
					qg.Increment("github")
				}

				r, err := client.Do(req)
				if err != nil {
					return true, err
				}

				if r.StatusCode == 403 || r.StatusCode == 429 {
					r.Body.Close()
					return true, fmt.Errorf("GitHub search rate limited: %d", r.StatusCode)
				}

				if r.StatusCode != 200 {
					r.Body.Close()
					return false, fmt.Errorf("GitHub search failed: %d", r.StatusCode)
				}

				resp = r
				return false, nil
			})

			if errSearch != nil {
				return
			}

			if resp == nil {
				return
			}
			defer resp.Body.Close()

			var searchResp githubSearchResponse
			if err := json.NewDecoder(io.LimitReader(resp.Body, 10*1024*1024)).Decode(&searchResp); err != nil {
				return
			}

			subdomainRegex := regexp.MustCompile(fmt.Sprintf(`(?i)([a-z0-9-_]+\.)*%s`, regexp.QuoteMeta(dom)))

			for _, item := range searchResp.Items {

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
				headers := scanCtx.Headers
				for k, v := range headers {
					rawReq.Header.Set(k, v)
				}

				var rawResp *http.Response
				rawCfg := RetryConfig{
					MaxRetries:     2,
					BaseDelay:      1 * time.Second,
					MaxDelay:       5 * time.Second,
					Multiplier:     2.0,
					JitterFraction: 0.2,
				}
				errRaw := ExecuteWithRetry(ctx, rawCfg, func(ctx context.Context, attempt int) (bool, error) {
					qg := scanCtx.QuotaGuard
					if qg != nil {
						qg.Increment("github")
					}

					r, err := client.Do(rawReq)
					if err != nil {
						return true, err
					}
					if r.StatusCode == 403 || r.StatusCode == 429 {
						r.Body.Close()
						return true, fmt.Errorf("github rate limit: %d", r.StatusCode)
					}
					if r.StatusCode != 200 {
						r.Body.Close()
						return false, fmt.Errorf("github raw download status: %d", r.StatusCode)
					}
					rawResp = r
					return false, nil
				})
				if errRaw != nil {
					continue
				}

				fileBody, err := io.ReadAll(io.LimitReader(rawResp.Body, 5*1024*1024))
				rawResp.Body.Close()
				if err != nil {
					continue
				}

				matches := subdomainRegex.FindAllString(string(fileBody), -1)
				for _, match := range matches {
					match = strings.ToLower(strings.TrimSpace(match))
					if match != "" {
						mu.Lock()
						events = append(events, recon.NewEvent(match, t.Name(), "subdomain", map[string]string{
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
