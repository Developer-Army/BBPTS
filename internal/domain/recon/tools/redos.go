package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type ReDoSTool struct{}

var redosPayloads = []struct {
	Name    string
	Payload string
	Field   string
}{
	{Name: "catastrophic_backtrack", Payload: strings.Repeat("a", 30) + "X", Field: "q"},
	{Name: "nested_quantifier", Payload: strings.Repeat("a", 25) + "!", Field: "q"},
	{Name: "email_redos", Payload: strings.Repeat("a", 20) + "@" + strings.Repeat("a", 20) + "." + strings.Repeat("a", 20), Field: "email"},
	{Name: "phone_redos", Payload: strings.Repeat("1", 30) + "!", Field: "phone"},
	{Name: "url_redos", Payload: "http://" + strings.Repeat("a", 20) + "." + strings.Repeat("a", 20), Field: "url"},
	{Name: "date_redos", Payload: strings.Repeat("2024-", 10) + "99", Field: "date"},
	{Name: "hex_redos", Payload: strings.Repeat("0x", 15) + "ff", Field: "hex"},
	{Name: "ipv4_redos", Payload: strings.Repeat("192.168.", 8) + "1", Field: "ip"},
	{Name: "csv_redos", Payload: strings.Repeat("a,b,", 15) + "c", Field: "csv"},
	{Name: "markdown_redos", Payload: strings.Repeat("**", 20) + "bold" + strings.Repeat("**", 20), Field: "text"},
}

func (t *ReDoSTool) Name() string {
	return "redos"
}

func (t *ReDoSTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 10
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

		client := NewSafeHTTPClient(30 * time.Second)
		var events []recon.Event

		baseline := t.measureBaseline(ctx, client, target, scanCtx.Headers)
		if baseline == 0 {
			return nil, nil
		}

		threshold := baseline * 3
		if threshold < 2*time.Second {
			threshold = 2 * time.Second
		}

		for _, payload := range redosPayloads {
			status, duration := t.sendPayload(ctx, client, target, payload, scanCtx.Headers)

			if status == 0 {
				continue
			}

			if duration > threshold && status != 429 {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":    "ReDoS (Regular Expression Denial of Service)",
					"severity":     "medium",
					"test":         payload.Name,
					"field":        payload.Field,
					"payload_len":  fmt.Sprintf("%d", len(payload.Payload)),
					"baseline_ms":  fmt.Sprintf("%d", baseline.Milliseconds()),
					"duration_ms":  fmt.Sprintf("%d", duration.Milliseconds()),
					"threshold_ms": fmt.Sprintf("%d", threshold.Milliseconds()),
					"status":       fmt.Sprintf("%d", status),
					"description":  fmt.Sprintf("Server-side regex DoS: %s took %dms (baseline: %dms, threshold: %dms)", payload.Name, duration.Milliseconds(), baseline.Milliseconds(), threshold.Milliseconds()),
				}, "medium"))
				slog.Warn("ReDoS detected", "target", target, "test", payload.Name, "duration", duration, "baseline", baseline)
				break
			}
		}

		return events, nil
	})
}

func (t *ReDoSTool) measureBaseline(ctx context.Context, client *http.Client, target string, headers map[string]string) time.Duration {
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return 0
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return time.Since(start)
}

func (t *ReDoSTool) sendPayload(ctx context.Context, client *http.Client, target string, payload struct{ Name, Payload, Field string }, headers map[string]string) (int, time.Duration) {
	parsed, err := url.Parse(target)
	if err != nil {
		return 0, 0
	}

	params := parsed.Query()
	params.Set(payload.Field, payload.Payload)
	parsed.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return 0, 0
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, 0
	}
	defer resp.Body.Close()
	duration := time.Since(start)

	return resp.StatusCode, duration
}

var _ recon.Tool = (*ReDoSTool)(nil)
