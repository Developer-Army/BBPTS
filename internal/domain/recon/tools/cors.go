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

type CORSTool struct{}

func (t *CORSTool) Name() string {
	return "cors"
}

func (t *CORSTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
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

		var events []recon.Event
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

			headers := scanCtx.Headers
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			req.Header.Set("Origin", test.origin)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			reqDump, _ := httputil.DumpRequestOut(req, true)
			respDump, _ := httputil.DumpResponse(resp, false)
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			resp.Body.Close()

			acao := resp.Header.Get("Access-Control-Allow-Origin")
			acac := resp.Header.Get("Access-Control-Allow-Credentials")

			if acao == test.origin && acac == "true" {
				mu.Lock()
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "CORS Misconfiguration",
					"severity":    "medium",
					"cors_type":   test.name,
					"origin":      test.origin,
					"method":      "GET",
					"description": fmt.Sprintf("Permissive CORS policy: Allow-Origin reflects %s with credentials enabled.", test.origin),
					"request":     string(reqDump),
					"response":    string(respDump),
				}, "medium"))
				mu.Unlock()
				slog.Warn("Found CORS misconfiguration", "target", target, "type", test.name, "method", "GET")
				break
			}

			preflightReq, err := http.NewRequestWithContext(ctx, "OPTIONS", target, nil)
			if err != nil {
				continue
			}
			for k, v := range headers {
				preflightReq.Header.Set(k, v)
			}
			preflightReq.Header.Set("Origin", test.origin)
			preflightReq.Header.Set("Access-Control-Request-Method", "GET")
			preflightReq.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")

			preflightResp, err := client.Do(preflightReq)
			if err != nil {
				continue
			}

			pfReqDump, _ := httputil.DumpRequestOut(preflightReq, true)
			pfRespDump, _ := httputil.DumpResponse(preflightResp, false)
			_, _ = io.Copy(io.Discard, io.LimitReader(preflightResp.Body, 4096))
			preflightResp.Body.Close()

			preflightACAO := preflightResp.Header.Get("Access-Control-Allow-Origin")
			preflightACAC := preflightResp.Header.Get("Access-Control-Allow-Credentials")

			if preflightACAO == test.origin && preflightACAC == "true" {
				mu.Lock()
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "CORS Misconfiguration (Preflight)",
					"severity":    "medium",
					"cors_type":   test.name,
					"origin":      test.origin,
					"method":      "OPTIONS",
					"description": fmt.Sprintf("Permissive CORS policy on preflight: Allow-Origin reflects %s with credentials enabled.", test.origin),
					"request":     string(pfReqDump),
					"response":    string(pfRespDump),
				}, "medium"))
				mu.Unlock()
				slog.Warn("Found CORS misconfiguration (preflight)", "target", target, "type", test.name)
				break
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

var _ recon.Tool = (*CORSTool)(nil)
