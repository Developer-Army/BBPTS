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

type GitExposureTool struct{}

func (t *GitExposureTool) Name() string {
	return "git_exposure"
}

var (
	gitSecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|token|access[_-]?token)\s*[:=]\s*["']([^"']{8,})["']`),
		regexp.MustCompile(`(?i)(?:aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)`),
	}
)

func (t *GitExposureTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

		base, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event

		// Target paths
		headURL := fmt.Sprintf("%s://%s/.git/HEAD", base.Scheme, base.Host)
		configURL := fmt.Sprintf("%s://%s/.git/config", base.Scheme, base.Host)

		// 1. Probe /.git/HEAD
		hReq, err := http.NewRequestWithContext(ctx, "GET", headURL, nil)
		if err != nil {
			return nil, nil
		}
		for k, v := range scanCtx.Headers {
			hReq.Header.Set(k, v)
		}

		hResp, err := client.Do(hReq)
		if err == nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(hResp.Body, 1024))
			hResp.Body.Close()
			bodyStr := string(bodyBytes)

			if hResp.StatusCode == 200 && (strings.HasPrefix(bodyStr, "ref: refs/") || len(bodyStr) == 41 /* SHA1 hash length + newline */) {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Exposed Git Repository",
					"severity":    "high",
					"url":         headURL,
					"evidence":    strings.TrimSpace(bodyStr),
					"description": fmt.Sprintf("Exposed Git directory discovered at %s", target),
				}, "high"))

				// 2. Probe /.git/config to extract extra credentials or remote URLs
				cReq, err := http.NewRequestWithContext(ctx, "GET", configURL, nil)
				if err == nil {
					for k, v := range scanCtx.Headers {
						cReq.Header.Set(k, v)
					}
					cResp, err := client.Do(cReq)
					if err == nil {
						cBody, _ := io.ReadAll(io.LimitReader(cResp.Body, 64*1024))
						cResp.Body.Close()
						cStr := string(cBody)

						if cResp.StatusCode == 200 && strings.Contains(cStr, "[core]") {
							// Scan config for secrets
							foundSecrets := []string{}
							for _, r := range gitSecretPatterns {
								if m := r.FindString(cStr); m != "" {
									foundSecrets = append(foundSecrets, m)
								}
							}

							// Check for remote URLs
							remoteURL := ""
							re := regexp.MustCompile(`url\s*=\s*([^\s]+)`)
							if match := re.FindStringSubmatch(cStr); len(match) > 1 {
								remoteURL = match[1]
							}

							props := map[string]string{
								"vuln_name":   "Git Configuration Exposure",
								"severity":    "high",
								"url":         configURL,
								"evidence":    cStr,
								"description": fmt.Sprintf("Exposed Git config file discovered at %s. Remote URL: %s", configURL, remoteURL),
							}
							if len(foundSecrets) > 0 {
								props["secrets"] = strings.Join(foundSecrets, ", ")
								props["severity"] = "critical"
							}

							events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", props, props["severity"]))
						}
					}
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*GitExposureTool)(nil)
