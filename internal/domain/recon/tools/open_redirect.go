package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type OpenRedirectTool struct{}

func (t *OpenRedirectTool) Name() string {
	return "open_redirect"
}

var redirectParams = []string{
	"url", "redirect", "redirect_url", "redirect_uri", "redirecturl", "redirecturi",
	"next", "return", "return_url", "returnurl", "return_to", "returnto",
	"r", "u", "ref", "referer", "referrer",
	"dest", "destination", "goto", "go", "to",
	"out", "view", "link", "continue", "target",
	"forward", "location", "from", "source",
	"callback", "cb", "service", "success", "cancel",
	"logout_redirect", "login_redirect", "auth_redirect",
	"back", "backUrl", "back_url", "origin", "path",
}

func inScopeHost(location, originalHost string) bool {
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	locHost := u.Hostname()
	if locHost == "" {

		return true
	}
	return strings.EqualFold(locHost, originalHost) ||
		strings.HasSuffix(strings.ToLower(locHost), "."+strings.ToLower(originalHost))
}

func (t *OpenRedirectTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 40
	}
	pool := NewWorkerPoolWithName(threads, rate.Limit(rateLimit), t.Name())

	oobURL := scanCtx.InteractshOOBURL
	evilCanary := "https://open-redirect-canary.evil.invalid"
	if oobURL != "" {
		evilCanary = "https://" + strings.TrimPrefix(strings.TrimPrefix(oobURL, "https://"), "http://")
	}

	// dedup: track (host, param) pairs we already confirmed vulnerable.
	var dedupMu sync.Mutex
	confirmed := make(map[string]struct{})

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			return nil, nil
		}

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}
		originalHost := parsed.Hostname()

		client := NewSafeHTTPClient(6 * time.Second)

		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event

		query := parsed.Query()
		for _, param := range redirectParams {
			if query.Get(param) == "" {
				continue
			}

			modified := parsed.Query()
			modified.Set(param, evilCanary)
			testURL := *parsed
			testURL.RawQuery = modified.Encode()

			ev := t.probe(ctx, client, target, testURL.String(), param, evilCanary, originalHost, oobURL)
			if ev != nil {
				key := originalHost + "|" + param
				dedupMu.Lock()
				_, seen := confirmed[key]
				if !seen {
					confirmed[key] = struct{}{}
					events = append(events, *ev)
				}
				dedupMu.Unlock()
				break
			}
		}

		basePaths := []string{
			"",
			"/logout", "/signout", "/sign-out", "/logoff",
			"/login", "/signin", "/sign-in",
			"/auth/callback", "/oauth/callback", "/sso",
			"/redirect", "/go", "/out", "/external",
		}
		for _, basePath := range basePaths {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
			baseURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, basePath)
			for _, param := range redirectParams[:16] {
				key := originalHost + "|" + param
				dedupMu.Lock()
				_, seen := confirmed[key]
				dedupMu.Unlock()
				if seen {
					continue
				}

				testURL := baseURL + "?" + param + "=" + url.QueryEscape(evilCanary)
				ev := t.probe(ctx, client, baseURL, testURL, param, evilCanary, originalHost, oobURL)
				if ev != nil {
					dedupMu.Lock()
					_, seen2 := confirmed[key]
					if !seen2 {
						confirmed[key] = struct{}{}
						events = append(events, *ev)
					}
					dedupMu.Unlock()
				}
			}
		}

		return events, nil
	})
}

func (t *OpenRedirectTool) probe(
	ctx context.Context, client *http.Client,
	originalTarget, testURL, param, canary, originalHost, oobURL string,
) *recon.Event {
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "text/html,*/*")

	reqDump, _ := httputil.DumpRequestOut(req, false)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	respDump, _ := httputil.DumpResponse(resp, false)
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if loc == "" {
			return nil
		}

		if !strings.Contains(loc, "open-redirect-canary.evil") &&
			!strings.Contains(loc, oobURL) &&
			!strings.HasPrefix(loc, canary) {
			return nil
		}
		if inScopeHost(loc, originalHost) {
			return nil
		}
		slog.Warn("Open redirect confirmed", "target", originalTarget, "param", param, "location", loc)
		ev := recon.NewEventWithSeverity(originalTarget, "open_redirect", "vulnerability", map[string]string{
			"vuln_name":   "Open Redirect",
			"severity":    "medium",
			"param":       param,
			"test_url":    testURL,
			"location":    loc,
			"status":      fmt.Sprintf("%d", resp.StatusCode),
			"description": fmt.Sprintf("Server redirected to external destination via parameter '%s'. Location: %s", param, loc),
			"request":     string(reqDump),
			"response":    string(respDump),
		}, "medium")
		return &ev
	}

	if oobURL != "" && resp.StatusCode == 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32*1024))
		bodyStr := strings.ToLower(string(body))
		oobLower := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(oobURL, "https://"), "http://"))
		if strings.Contains(bodyStr, oobLower) || strings.Contains(bodyStr, "open-redirect-canary") {
			slog.Warn("Open redirect in body (meta/JS)", "target", originalTarget, "param", param)
			ev := recon.NewEventWithSeverity(originalTarget, "open_redirect", "vulnerability", map[string]string{
				"vuln_name":   "Open Redirect (Client-Side)",
				"severity":    "medium",
				"param":       param,
				"test_url":    testURL,
				"description": fmt.Sprintf("OOB canary URL appeared in response body via '%s' — meta-refresh or JS redirect likely.", param),
				"request":     string(reqDump),
				"response":    string(respDump),
			}, "medium")
			return &ev
		}
	}

	return nil
}

var _ recon.Tool = (*OpenRedirectTool)(nil)
