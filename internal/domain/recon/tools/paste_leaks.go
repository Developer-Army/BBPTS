package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type PasteLeaksTool struct{}

func (t *PasteLeaksTool) Name() string {
	return "paste_leaks"
}

type psbdmpSearchResult struct {
	ID string `json:"id"`
}

var (
	psbdmpBaseURL   = "https://psbdmp.ws"
	pasteSecretRegex = regexp.MustCompile(`(?i)(?:api_key|password|db_conn|secret_key|private_key|token)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{12,})["']?`)
)

func (t *PasteLeaksTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

		host := target
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			u, err := url.Parse(target)
			if err == nil {
				host = u.Hostname()
			}
		}

		client := NewSafeHTTPClient(10 * time.Second)
		searchURL := fmt.Sprintf("%s/api/search/%s", psbdmpBaseURL, url.QueryEscape(host))

		req, err := http.NewRequestWithContext(ctx, "GET", searchURL, nil)
		if err != nil {
			return nil, nil
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil
		}
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()

		var results []psbdmpSearchResult
		if err := json.Unmarshal(bodyBytes, &results); err != nil {
			// If not a JSON array, try parsing it as a single object or skip
			return nil, nil
		}

		var events []recon.Event

		// Limit paste content fetches to avoid hitting rate limits
		maxPastes := len(results)
		if maxPastes > 5 {
			maxPastes = 5
		}

		for i := 0; i < maxPastes; i++ {
			pasteID := results[i].ID
			pasteURL := fmt.Sprintf("%s/api/dump/%s", psbdmpBaseURL, pasteID)

			pReq, err := http.NewRequestWithContext(ctx, "GET", pasteURL, nil)
			if err != nil {
				continue
			}

			pResp, err := client.Do(pReq)
			if err != nil {
				continue
			}
			pBodyBytes, _ := io.ReadAll(io.LimitReader(pResp.Body, 256*1024))
			pResp.Body.Close()
			pStr := string(pBodyBytes)

			if matches := pasteSecretRegex.FindAllStringSubmatch(pStr, -1); len(matches) > 0 {
				var leaked []string
				for _, match := range matches {
					if len(match) > 1 {
						leaked = append(leaked, match[0])
					}
				}

				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Sensitive Data Exposure in Public Paste",
					"severity":    "high",
					"paste_id":    pasteID,
					"evidence":    strings.Join(leaked, ", "),
					"description": fmt.Sprintf("Leaked credential / secret matching domain %s was found in public paste dump %s", host, pasteID),
				}, "high"))
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*PasteLeaksTool)(nil)
