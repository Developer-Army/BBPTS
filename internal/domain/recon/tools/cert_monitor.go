package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type CertMonitorTool struct{}

func (t *CertMonitorTool) Name() string {
	return "cert_monitor"
}

type certMonitorCrtshEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

var crtshAPIURL = "https://crt.sh"

func (t *CertMonitorTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 5
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		host := target
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			u, err := url.Parse(target)
			if err == nil {
				host = u.Hostname()
			}
		}

		client := NewSafeHTTPClient(15 * time.Second)
		queryURL := fmt.Sprintf("%s/?q=%%.%s&output=json", crtshAPIURL, host)

		req, err := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
		if err != nil {
			return nil, nil
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
		resp.Body.Close()

		var entries []certMonitorCrtshEntry
		if err := json.Unmarshal(bodyBytes, &entries); err != nil {
			return nil, nil
		}

		var events []recon.Event
		seenSubdomains := make(map[string]bool)

		for _, entry := range entries {
			sub := strings.TrimSpace(entry.CommonName)
			if sub != "" && !strings.Contains(sub, "*") && strings.HasSuffix(sub, host) {
				if !seenSubdomains[sub] {
					seenSubdomains[sub] = true
					events = append(events, recon.NewEvent(sub, t.Name(), "discovery", map[string]string{
						"type":   "subdomain",
						"source": "cert_monitor",
					}))
				}
			}

			subNames := strings.Split(entry.NameValue, "\n")
			for _, sub := range subNames {
				sub = strings.TrimSpace(sub)
				if sub != "" && !strings.Contains(sub, "*") && strings.HasSuffix(sub, host) {
					if !seenSubdomains[sub] {
						seenSubdomains[sub] = true
						events = append(events, recon.NewEvent(sub, t.Name(), "discovery", map[string]string{
							"type":   "subdomain",
							"source": "cert_monitor",
						}))
					}
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*CertMonitorTool)(nil)
