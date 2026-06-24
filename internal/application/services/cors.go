package services

import (
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

type CORSTool struct{}

func (t *CORSTool) Name() string {
	return "cors"
}

func (t *CORSTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
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

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		domain := parsed.Hostname()
		rootDomain := getRootDomain(domain)

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []Event
		var mu sync.Mutex

		tests := []struct {
			name   string
			origin string
		}{
			{"Origin Reflection", "https://evil.com"},
			{"Null Origin", "null"},
			{"Subdomain Trust", "https://evil." + rootDomain},
		}

		for _, test := range tests {
			req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
			if err != nil {
				continue
			}

			// Add custom headers & cookie
			headers := HeadersFromCtx(ctx)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			req.Header.Set("Origin", test.origin)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			resp.Body.Close()

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := resp.Header.Get("Access-Control-Allow-Credentials")

			if acao == test.origin && acac == "true" {
				mu.Lock()
				events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "CORS Misconfiguration",
					"severity":    "medium",
					"cors_type":   test.name,
					"origin":      test.origin,
					"description": fmt.Sprintf("Permissive CORS policy: Allow-Origin reflects %s with credentials enabled.", test.origin),
				}, "medium"))
				mu.Unlock()
				slog.Warn("Found CORS misconfiguration", "target", target, "type", test.name)
				break // One CORS finding is enough per host
			}
		}

		return events, nil
	})
}

func getRootDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) > 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return host
}

var _ Tool = (*CORSTool)(nil)
