package services

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
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

		candidates := []string{}
		if looksLikeOAuthAuthorizeURL(parsed) {
			candidates = append(candidates, parsed.String())
		} else {
			candidates = append(candidates, t.discoverOAuthCandidates(ctx, parsed.String())...)
		}
		if len(candidates) == 0 {
			return nil, nil
		}

		var events []Event

		for _, candidate := range dedupeStrings(candidates) {
			parsedCandidate, err := url.Parse(candidate)
			if err != nil {
				continue
			}
			if !looksLikeOAuthAuthorizeURL(parsedCandidate) {
				continue
			}
			q := parsedCandidate.Query()
			slog.Info("Discovered potential OAuth 2.0 endpoint", "url", candidate)

			// Test 1: Missing state parameter (CSRF)
			if q.Get("state") != "" {
				testQ := parsedCandidate.Query()
				testQ.Del("state")
				testURL := *parsedCandidate
				testURL.RawQuery = testQ.Encode()

				ok, testErr := t.checkAuthSuccess(ctx, testURL.String())
				if testErr == nil && ok {
					events = append(events, NewEventWithSeverity(candidate, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "OAuth 2.0 Missing State Parameter (CSRF)",
						"severity":    "medium",
						"description": fmt.Sprintf("OAuth authorize endpoint at %s does not enforce the 'state' parameter, exposing users to OAuth login CSRF.", candidate),
					}, "medium"))
				}
			}

			// Test 2: Open redirect_uri (OAuth hijacking)
			if q.Get("redirect_uri") != "" {
				testQ := parsedCandidate.Query()
				evilDomain := "https://example.com"
				testQ.Set("redirect_uri", evilDomain)
				testURL := *parsedCandidate
				testURL.RawQuery = testQ.Encode()

				redirected, loc, testErr := t.checkOpenRedirect(ctx, testURL.String(), evilDomain)
				if testErr == nil && redirected {
					events = append(events, NewEventWithSeverity(candidate, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "OAuth 2.0 Open redirect_uri (Account Takeover)",
						"severity":    "high",
						"redirect_to": loc,
						"description": fmt.Sprintf("OAuth authorize endpoint at %s redirects to unvalidated 'redirect_uri' (%s), allowing authorization code/token hijacking.", candidate, loc),
					}, "high"))
				}
			}

			// Test 3: Implicit flow enabled (Token leakage)
			if q.Get("response_type") != "" && q.Get("response_type") != "token" {
				testQ := parsedCandidate.Query()
				testQ.Set("response_type", "token")
				testURL := *parsedCandidate
				testURL.RawQuery = testQ.Encode()

				ok, testErr := t.checkAuthSuccess(ctx, testURL.String())
				if testErr == nil && ok {
					events = append(events, NewEventWithSeverity(candidate, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "OAuth 2.0 Implicit Flow Enabled",
						"severity":    "low",
						"description": fmt.Sprintf("OAuth authorize endpoint at %s accepts 'response_type=token', enabling insecure implicit flow token leakage via URL fragment.", candidate),
					}, "low"))
				}
			}

			// Test 4: PKCE Bypass
			if q.Get("code_challenge") != "" {
				testQ := parsedCandidate.Query()
				testQ.Del("code_challenge")
				testQ.Del("code_challenge_method")
				testURL := *parsedCandidate
				testURL.RawQuery = testQ.Encode()

				ok, testErr := t.checkAuthSuccess(ctx, testURL.String())
				if testErr == nil && ok {
					events = append(events, NewEventWithSeverity(candidate, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "OAuth 2.0 PKCE Bypass",
						"severity":    "medium",
						"description": fmt.Sprintf("OAuth authorize endpoint at %s allows flow completion without the required PKCE code_challenge.", candidate),
					}, "medium"))
				}
			}
		}

		return events, nil
	})
}

func looksLikeOAuthAuthorizeURL(parsed *url.URL) bool {
	q := parsed.Query()
	hasClientID := q.Get("client_id") != ""
	hasResponseType := q.Get("response_type") != ""
	path := strings.ToLower(parsed.Path)
	isAuthorizePath := strings.Contains(path, "authorize") || strings.Contains(path, "oauth") || strings.Contains(path, "auth")
	return (hasClientID && hasResponseType) || (isAuthorizePath && (hasClientID || hasResponseType))
}

func (t *OAuthTesterTool) discoverOAuthCandidates(ctx context.Context, target string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	for k, v := range HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	baseURL := resp.Request.URL

	candidates := extractOAuthCandidatesFromText(baseURL, string(body), resp.Header)
	scriptSrcRe := regexp.MustCompile(`(?i)<script[^>]+\bsrc=["']([^"']+)["']`)
	for _, match := range scriptSrcRe.FindAllStringSubmatch(string(body), -1) {
		scriptURL := resolveReference(baseURL, match[1])
		if scriptURL == "" {
			continue
		}
		scriptReq, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
		if err != nil {
			continue
		}
		for k, v := range HeadersFromCtx(ctx) {
			scriptReq.Header.Set(k, v)
		}
		scriptResp, err := t.client.Do(scriptReq)
		if err != nil {
			continue
		}
		scriptBody, _ := io.ReadAll(io.LimitReader(scriptResp.Body, 512*1024))
		scriptResp.Body.Close()
		candidates = append(candidates, extractOAuthCandidatesFromText(baseURL, string(scriptBody), scriptResp.Header)...)
	}
	return dedupeStrings(candidates)
}

func extractOAuthCandidatesFromText(base *url.URL, text string, headers http.Header) []string {
	var candidates []string
	for _, link := range headers.Values("Link") {
		for _, part := range strings.Split(link, ",") {
			partLower := strings.ToLower(part)
			if !strings.Contains(partLower, "oauth") && !strings.Contains(partLower, "auth") {
				continue
			}
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start >= 0 && end > start {
				if resolved := resolveReference(base, strings.TrimSpace(part[start+1:end])); resolved != "" {
					candidates = append(candidates, resolved)
				}
			}
		}
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']*(?:oauth|authorize|client_id)[^"']*)["']`),
		regexp.MustCompile(`(?i)(https?://[^"'` + "`" + `\s]+(?:oauth|authorize|auth)[^"'` + "`" + `\s]*)`),
		regexp.MustCompile(`(?i)window\.location(?:\.href)?\s*=\s*["']([^"']*(?:oauth|authorize|auth)[^"']*)["']`),
	}
	for _, re := range patterns {
		for _, match := range re.FindAllStringSubmatch(text, -1) {
			if len(match) < 2 {
				continue
			}
			if resolved := resolveReference(base, strings.TrimSpace(match[1])); resolved != "" {
				candidates = append(candidates, resolved)
			}
		}
	}

	clientIDRe := regexp.MustCompile(`(?i)(?:oauth_)?client_id["']?\s*[:=]\s*["']([^"']+)["']`)
	if match := clientIDRe.FindStringSubmatch(text); len(match) == 2 && base != nil {
		u := *base
		u.Path = "/oauth/authorize"
		q := url.Values{}
		q.Set("client_id", match[1])
		q.Set("response_type", "code")
		u.RawQuery = q.Encode()
		candidates = append(candidates, u.String())
	}

	return candidates
}

func resolveReference(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || base == nil {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(u).String()
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
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
