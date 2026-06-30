package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type PriceLogicTool struct{}

func (t *PriceLogicTool) Name() string {
	return "price_logic"
}

func (t *PriceLogicTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event

		checkoutPaths := []string{
			"/api/cart",
			"/api/checkout",
			"/api/v1/cart",
			"/api/v1/checkout",
		}

		for _, cPath := range checkoutPaths {
			checkoutURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, cPath)

			payloads := []string{
				`{"price": -1, "quantity": 1, "product_id": "1"}`,
				`{"amount": 0.01, "quantity": 1, "product_id": "1"}`,
				`{"price": 0, "quantity": 1, "product_id": "1"}`,
			}

			for _, pay := range payloads {
				req, err := http.NewRequestWithContext(ctx, "POST", checkoutURL, strings.NewReader(pay))
				if err != nil {
					continue
				}
				req.Header.Set("Content-Type", "application/json")
				for k, v := range scanCtx.Headers {
					req.Header.Set(k, v)
				}

				resp, err := client.Do(req)
				if err == nil {
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
					resp.Body.Close()
					bodyStr := strings.ToLower(string(bodyBytes))

					if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated) &&
						!strings.Contains(bodyStr, "error") && !strings.Contains(bodyStr, "invalid") && !strings.Contains(bodyStr, "failed") {
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Parameter Tampering: Price Logic Bypass",
							"severity":    "high",
							"url":         checkoutURL,
							"payload":     pay,
							"evidence":    bodyStr,
							"description": fmt.Sprintf("Price logic parameter tampering accepted at %s. Payload %s returned status %d.", checkoutURL, pay, resp.StatusCode),
						}, "high"))
					}
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*PriceLogicTool)(nil)
