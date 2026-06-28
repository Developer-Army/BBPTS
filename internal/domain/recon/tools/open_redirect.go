package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"log/slog"
	"net/http"
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

func (t *OpenRedirectTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	redirectParams := []string{"url", "redirect", "next", "return", "r", "dest", "destination", "go", "to", "out", "view", "link"}

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

		// Identify targets containing redirect parameters
		query := parsed.Query()
		foundParam := ""
		for _, param := range redirectParams {
			if query.Get(param) != "" {
				foundParam = param
				break
			}
		}

		if foundParam == "" {
			return nil, nil
		}

		// Inject external target
		evilTarget := "https://example.com"
		query.Set(foundParam, evilTarget)
		parsed.RawQuery = query.Encode()
		evilURL := parsed.String()

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event
		var mu sync.Mutex

		req, err := http.NewRequestWithContext(ctx, "GET", evilURL, nil)
		if err != nil {
			return nil, nil
		}
		headers := scanCtx.Headers
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil
		}
		resp.Body.Close()

		loc := resp.Header.Get("Location")
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && (strings.HasPrefix(loc, evilTarget) || strings.HasPrefix(loc, "//example.com")) {
			mu.Lock()
			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Open Redirect Misconfiguration",
				"severity":    "medium",
				"param":       foundParam,
				"url":         evilURL,
				"location":    loc,
				"description": fmt.Sprintf("Unvalidated open redirect via parameter '%s' pointing to %s.", foundParam, loc),
			}, "medium"))
			mu.Unlock()
			slog.Warn("Found open redirect misconfiguration", "target", target, "param", foundParam)
		}

		return events, nil
	})
}

var _ recon.Tool = (*OpenRedirectTool)(nil)
