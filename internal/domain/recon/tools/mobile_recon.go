package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type MobileReconTool struct{}

func (t *MobileReconTool) Name() string {
	return "mobile_recon"
}

var (
	deepLinkPattern = regexp.MustCompile(`(?i)(?:scheme|host|android:scheme|android:host)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{3,})["']?`)
	apiKeyPattern   = regexp.MustCompile(`(?i)(?:api_key|client_secret|aws_key|firebase_key)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{15,})["']?`)
	apiKeyXmlPattern = regexp.MustCompile(`(?i)(?:api_key|client_secret|aws_key|firebase_key|secret|token|password|key)"\s+android:value="([a-zA-Z0-9_\-\.]{15,})"`)
)

func (t *MobileReconTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

		// Test 1: Check public mobile app config files or exposed manifests
		manifestPaths := []string{
			"/AndroidManifest.xml",
			"/static/AndroidManifest.xml",
			"/assets/app.json",
			"/app.json",
		}

		for _, mPath := range manifestPaths {
			manifestURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, mPath)
			req, err := http.NewRequestWithContext(ctx, "GET", manifestURL, nil)
			if err != nil {
				continue
			}
			for k, v := range scanCtx.Headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err == nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				if resp.StatusCode == 200 {
					// Scan for deep links
					if links := deepLinkPattern.FindAllStringSubmatch(bodyStr, -1); len(links) > 0 {
						var parsedLinks []string
						for _, match := range links {
							if len(match) > 1 {
								parsedLinks = append(parsedLinks, match[1])
							}
						}
						events = append(events, recon.NewEvent(manifestURL, t.Name(), "discovery", map[string]string{
							"type":       "mobile_deep_link",
							"deep_links": strings.Join(parsedLinks, ", "),
						}))
					}

					// Scan for hardcoded API keys/secrets
					var foundKeys []string
					if keys := apiKeyPattern.FindAllStringSubmatch(bodyStr, -1); len(keys) > 0 {
						for _, match := range keys {
							if len(match) > 1 {
								foundKeys = append(foundKeys, match[0])
							}
						}
					}
					if keys := apiKeyXmlPattern.FindAllStringSubmatch(bodyStr, -1); len(keys) > 0 {
						for _, match := range keys {
							if len(match) > 1 {
								foundKeys = append(foundKeys, match[0])
							}
						}
					}

					if len(foundKeys) > 0 {
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Hardcoded Secrets in Exposed Mobile App Resource",
							"severity":    "high",
							"url":         manifestURL,
							"evidence":    strings.Join(foundKeys, ", "),
							"description": fmt.Sprintf("Hardcoded API keys or client secrets discovered in public mobile resource at %s", manifestURL),
						}, "high"))
					}
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*MobileReconTool)(nil)
