package services

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"golang.org/x/time/rate"
)

type OAuthTesterTool struct {
	client *network.StealthClient
}

func (t *OAuthTesterTool) Name() string {
	return "oauth"
}

func (t *OAuthTesterTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}

	proxies := GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}

	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	var err error
	t.client, err = network.NewStealthClient(profile, proxy)
	if err != nil {
		slog.Warn("Failed to initialize stealth client in oauth tester", "error", err)
	} else if t.client != nil {
		t.client.SetCustomHeaders(HeadersFromCtx(ctx))
	}

	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]Event, error) {
		target = strings.TrimSpace(target)
		if target == "" || !strings.HasPrefix(target, "http") {
			return nil, nil
		}

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		// Detect if this URL looks like an OAuth Authorization Endpoint
		q := parsed.Query()
		hasClientID := q.Get("client_id") != ""
		hasResponseType := q.Get("response_type") != ""
		isAuthorizePath := strings.Contains(parsed.Path, "authorize") || strings.Contains(parsed.Path, "auth")

		if !((hasClientID && hasResponseType) || (isAuthorizePath && (hasClientID || hasResponseType))) {
			return nil, nil
		}

		slog.Info("Discovered potential OAuth 2.0 endpoint", "url", target)

		var events []Event

		// Test 1: Missing state parameter (CSRF)
		if q.Get("state") != "" {
			testQ := parsed.Query()
			testQ.Del("state")
			testURL := *parsed
			testURL.RawQuery = testQ.Encode()

			ok, testErr := t.checkAuthSuccess(ctx, testURL.String())
			if testErr == nil && ok {
				events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "OAuth 2.0 Missing State Parameter (CSRF)",
					"severity":    "medium",
					"description": fmt.Sprintf("OAuth authorize endpoint at %s does not enforce the 'state' parameter, exposing users to OAuth login CSRF.", target),
				}, "medium"))
			}
		}

		// Test 2: Open redirect_uri (OAuth hijacking)
		if q.Get("redirect_uri") != "" {
			testQ := parsed.Query()
			evilDomain := "https://example.com"
			testQ.Set("redirect_uri", evilDomain)
			testURL := *parsed
			testURL.RawQuery = testQ.Encode()

			redirected, loc, testErr := t.checkOpenRedirect(ctx, testURL.String(), evilDomain)
			if testErr == nil && redirected {
				events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "OAuth 2.0 Open redirect_uri (Account Takeover)",
					"severity":    "high",
					"redirect_to": loc,
					"description": fmt.Sprintf("OAuth authorize endpoint at %s redirects to unvalidated 'redirect_uri' (%s), allowing authorization code/token hijacking.", target, loc),
				}, "high"))
			}
		}

		// Test 3: Implicit flow enabled (Token leakage)
		if q.Get("response_type") != "" && q.Get("response_type") != "token" {
			testQ := parsed.Query()
			testQ.Set("response_type", "token")
			testURL := *parsed
			testURL.RawQuery = testQ.Encode()

			ok, testErr := t.checkAuthSuccess(ctx, testURL.String())
			if testErr == nil && ok {
				events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "OAuth 2.0 Implicit Flow Enabled",
					"severity":    "low",
					"description": fmt.Sprintf("OAuth authorize endpoint at %s accepts 'response_type=token', enabling insecure implicit flow token leakage via URL fragment.", target),
				}, "low"))
			}
		}

		// Test 4: PKCE Bypass
		if q.Get("code_challenge") != "" {
			testQ := parsed.Query()
			testQ.Del("code_challenge")
			testQ.Del("code_challenge_method")
			testURL := *parsed
			testURL.RawQuery = testQ.Encode()

			ok, testErr := t.checkAuthSuccess(ctx, testURL.String())
			if testErr == nil && ok {
				events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "OAuth 2.0 PKCE Bypass",
					"severity":    "medium",
					"description": fmt.Sprintf("OAuth authorize endpoint at %s allows flow completion without the required PKCE code_challenge.", target),
				}, "medium"))
			}
		}

		return events, nil
	})
}

func (t *OAuthTesterTool) checkAuthSuccess(ctx context.Context, testURL string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false, err
	}

	resp, err := t.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	// If it succeeds with 200 (prompting user login) or redirects to login/consents (302) without a 400 Bad Request
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		return true, nil
	}
	return false, nil
}

func (t *OAuthTesterTool) checkOpenRedirect(ctx context.Context, testURL string, evilDomain string) (bool, string, error) {
	client := NewSafeHTTPClient(5 * time.Second)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return false, "", err
	}
	headers := HeadersFromCtx(ctx)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	loc := resp.Header.Get("Location")
	if resp.StatusCode >= 300 && resp.StatusCode < 400 && (strings.HasPrefix(loc, evilDomain) || strings.HasPrefix(loc, "//example.com")) {
		return true, loc, nil
	}
	return false, "", nil
}

var _ Tool = (*OAuthTesterTool)(nil)
