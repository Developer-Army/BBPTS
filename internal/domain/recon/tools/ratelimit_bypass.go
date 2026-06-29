package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type RateLimitBypassTool struct{}

var bypassHeaders = []string{
	"X-Forwarded-For",
	"X-Real-IP",
	"True-Client-IP",
	"CF-Connecting-IP",
	"X-Client-IP",
	"Forwarded",
	"X-Forwarded",
	"X-Originating-IP",
	"X-Remote-IP",
	"X-Remote-Addr",
	"X-ProxyUser-Ip",
}

func (t *RateLimitBypassTool) Name() string {
	return "ratelimit_bypass"
}

func (t *RateLimitBypassTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 20
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

		client := NewSafeHTTPClient(10 * time.Second)

		// Step 1: Send initial request to establish baseline
		baselineStatus, baselineBody := t.doRequest(ctx, client, target, nil, scanCtx.Headers)
		if baselineStatus == 0 {
			return nil, nil
		}

		// If not rate limited, nothing to bypass
		if baselineStatus != 429 && !isRateLimitedBody(baselineBody) {
			return nil, nil
		}

		slog.Info("Rate limit detected, testing bypasses", "target", target, "status", baselineStatus)
		var events []recon.Event

		// Step 2: Test IP header injection bypasses
		for _, header := range bypassHeaders {
			for _, ip := range []string{"127.0.0.1", "8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"} {
				testHeaders := copyHeaders(scanCtx.Headers)
				testHeaders[header] = ip

				status, body := t.doRequest(ctx, client, target, nil, testHeaders)
				if status == 0 {
					continue
				}

				if status != 429 && !isRateLimitedBody(body) {
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":    "Rate Limit Bypass via Header Injection",
						"severity":     "high",
						"bypass_type":  "header_injection",
						"header":       header,
						"value":        ip,
						"baseline":     fmt.Sprintf("%d", baselineStatus),
						"bypass_status": fmt.Sprintf("%d", status),
						"description":  fmt.Sprintf("Rate limit bypassed by setting %s: %s (baseline: %d, bypass: %d)", header, ip, baselineStatus, status),
					}, "high"))
					slog.Warn("Rate limit bypass found", "target", target, "header", header, "value", ip, "status", status)
					return events, nil
				}
			}
		}

		// Step 3: Test URL parameter rotation
		urlVariants := []string{
			target + "?v=1",
			target + "?v=2",
			target + "?_=" + fmt.Sprintf("%d", time.Now().UnixNano()),
			target + "?nocache=1",
		}
		for _, variant := range urlVariants {
			status, body := t.doRequest(ctx, client, variant, nil, scanCtx.Headers)
			if status == 0 {
				continue
			}
			if status != 429 && !isRateLimitedBody(body) {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":    "Rate Limit Bypass via URL Parameter",
					"severity":     "high",
					"bypass_type":  "url_parameter",
					"variant":      variant,
					"baseline":     fmt.Sprintf("%d", baselineStatus),
					"bypass_status": fmt.Sprintf("%d", status),
					"description":  fmt.Sprintf("Rate limit bypassed by adding query parameter: %s", variant),
				}, "high"))
				slog.Warn("Rate limit bypass via URL param", "target", target, "variant", variant)
				return events, nil
			}
		}

		// Step 4: Test case variation
		if strings.HasSuffix(target, "/") {
			variant := strings.TrimSuffix(target, "/")
			status, body := t.doRequest(ctx, client, variant, nil, scanCtx.Headers)
			if status != 429 && !isRateLimitedBody(body) && status != 0 {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":    "Rate Limit Bypass via Case Variation",
					"severity":     "high",
					"bypass_type":  "case_variation",
					"variant":      variant,
					"baseline":     fmt.Sprintf("%d", baselineStatus),
					"bypass_status": fmt.Sprintf("%d", status),
					"description":  fmt.Sprintf("Rate limit bypassed by removing trailing slash"),
				}, "high"))
				return events, nil
			}
		}

		// Step 5: Test HTTP method switching
		methods := []string{"POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}
		for _, method := range methods {
			status, body := t.doMethodRequest(ctx, client, target, method, nil, scanCtx.Headers)
			if status == 0 {
				continue
			}
			if status != 429 && !isRateLimitedBody(body) {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":    "Rate Limit Bypass via Method Switch",
					"severity":     "high",
					"bypass_type":  "method_switch",
					"method":       method,
					"baseline":     fmt.Sprintf("%d", baselineStatus),
					"bypass_status": fmt.Sprintf("%d", status),
					"description":  fmt.Sprintf("Rate limit bypassed by switching HTTP method to %s", method),
				}, "high"))
				slog.Warn("Rate limit bypass via method switch", "target", target, "method", method)
				return events, nil
			}
		}

		// Step 6: Test null byte in path
		nullVariants := []string{
			strings.TrimSuffix(target, "/") + "%00",
			strings.TrimSuffix(target, "/") + "%00.json",
			strings.TrimSuffix(target, "/") + ".json%00",
		}
		for _, variant := range nullVariants {
			status, body := t.doRequest(ctx, client, variant, nil, scanCtx.Headers)
			if status == 0 {
				continue
			}
			if status != 429 && !isRateLimitedBody(body) {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":    "Rate Limit Bypass via Null Byte",
					"severity":     "high",
					"bypass_type":  "null_byte",
					"variant":      variant,
					"baseline":     fmt.Sprintf("%d", baselineStatus),
					"bypass_status": fmt.Sprintf("%d", status),
					"description":  fmt.Sprintf("Rate limit bypassed by appending null byte to path"),
				}, "high"))
				return events, nil
			}
		}

		return events, nil
	})
}

func (t *RateLimitBypassTool) doRequest(ctx context.Context, client *http.Client, url string, body io.Reader, headers map[string]string) (int, []byte) {
	return t.doMethodRequest(ctx, client, url, "GET", body, headers)
}

func (t *RateLimitBypassTool) doMethodRequest(ctx context.Context, client *http.Client, url, method string, body io.Reader, headers map[string]string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	return resp.StatusCode, respBody
}

func isRateLimitedBody(body []byte) bool {
	s := strings.ToLower(string(body))
	rateLimitPatterns := []string{
		"rate limit",
		"too many requests",
		"throttl",
		"slow down",
		"429",
		"retry after",
		"limit exceeded",
	}
	for _, p := range rateLimitPatterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func copyHeaders(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

var _ recon.Tool = (*RateLimitBypassTool)(nil)
