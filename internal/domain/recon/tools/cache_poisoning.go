package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type CachePoisoningTool struct{}

func (t *CachePoisoningTool) Name() string {
	return "cache_poisoning"
}

func (t *CachePoisoningTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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
		if target == "" || !strings.HasPrefix(target, "http") {
			return nil, nil
		}

		var events []recon.Event

		poisonHost := "bbpts-poison-test.com"
		poisonPort := "8888"

		testHeaders := []struct {
			name  string
			value string
		}{
			{"X-Forwarded-Host", poisonHost},
			{"X-Forwarded-Port", poisonPort},
			{"X-Host", poisonHost},
			{"Forwarded", "host=" + poisonHost},
		}

		for _, th := range testHeaders {
			req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
			if err != nil {
				continue
			}

			ctxHeaders := scanCtx.Headers
			for k, v := range ctxHeaders {
				req.Header.Set(k, v)
			}

			req.Header.Set(th.name, th.value)

			// Use safe HTTP client and disable automatic redirect following to capture Location headers safely without triggering SSRF warnings.
			client := NewSafeHTTPClient(5 * time.Second)
			client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()

			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
			if err != nil {
				continue
			}
			bodyStr := string(bodyBytes)

			reflectedInHeader := false
			reflectedHeaderName := ""
			for hName, hValues := range resp.Header {
				for _, hVal := range hValues {
					if strings.Contains(hVal, th.value) {
						reflectedInHeader = true
						reflectedHeaderName = hName
						break
					}
				}
				if reflectedInHeader {
					break
				}
			}

			reflectedInBody := strings.Contains(bodyStr, th.value)

			if reflectedInHeader || reflectedInBody {
				desc := ""
				if reflectedInHeader {
					desc = fmt.Sprintf("Unkeyed header '%s: %s' reflected in response header '%s' of %s.", th.name, th.value, reflectedHeaderName, target)
				} else {
					desc = fmt.Sprintf("Unkeyed header '%s: %s' reflected in response body of %s.", th.name, th.value, target)
				}

				reqDump, _ := httputil.DumpRequestOut(req, false)
				var respBuilder strings.Builder
				respBuilder.WriteString(fmt.Sprintf("%s %s\r\n", resp.Proto, resp.Status))
				for k, v := range resp.Header {
					respBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", k, strings.Join(v, ", ")))
				}
				respBuilder.WriteString("\r\n")
				respBuilder.WriteString(bodyStr)

				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Host Header Injection / Cache Poisoning",
					"severity":    "medium",
					"header":      th.name,
					"value":       th.value,
					"description": desc,
					"request":     string(reqDump),
					"response":    respBuilder.String(),
				}, "medium"))
				break
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*CachePoisoningTool)(nil)
