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

type CloudExposureTool struct{}

func (t *CloudExposureTool) Name() string {
	return "cloud_exposure"
}

func (t *CloudExposureTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

		cloudFiles := []string{
			"/.aws/credentials",
			"/.gcloud/active_config",
			"/credentials.json",
		}

		for _, cfPath := range cloudFiles {
			fileURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, cfPath)
			req, err := http.NewRequestWithContext(ctx, "GET", fileURL, nil)
			if err != nil {
				continue
			}
			for k, v := range scanCtx.Headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err == nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
				resp.Body.Close()
				bodyStr := string(bodyBytes)

				if resp.StatusCode == 200 {
					isLeaked := false
					if strings.Contains(bodyStr, "aws_access_key_id") || strings.Contains(bodyStr, "aws_secret_access_key") {
						isLeaked = true
					} else if strings.Contains(bodyStr, "type") && strings.Contains(bodyStr, "project_id") && strings.Contains(bodyStr, "private_key") {
						isLeaked = true
					} else if strings.Contains(bodyStr, "configuration") && strings.Contains(bodyStr, "core") {
						isLeaked = true
					}

					if isLeaked {
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Exposed Cloud Credentials File",
							"severity":    "critical",
							"url":         fileURL,
							"evidence":    bodyStr,
							"description": fmt.Sprintf("Exposed cloud credentials/configuration file discovered at %s", fileURL),
						}, "critical"))
					}
				}
			}
		}

		host := parsed.Hostname()

		if !strings.Contains(host, "127.0.0.1") && !strings.Contains(host, "localhost") && strings.Contains(host, ".") {
			domainParts := strings.Split(host, ".")
			if len(domainParts) > 1 {
				targetName := domainParts[len(domainParts)-2]

				saasChecks := []struct {
					name string
					url  string
				}{
					{"Jira", fmt.Sprintf("https://%s.atlassian.net/rest/api/3/project", targetName)},
					{"Trello", fmt.Sprintf("https://trello.com/b/%s", targetName)},
				}

				for _, check := range saasChecks {
					sReq, err := http.NewRequestWithContext(ctx, "GET", check.url, nil)
					if err != nil {
						continue
					}
					sResp, err := client.Do(sReq)
					if err == nil {
						bodyBytes, _ := io.ReadAll(io.LimitReader(sResp.Body, 16*1024))
						sResp.Body.Close()
						bodyStr := string(bodyBytes)

						if sResp.StatusCode == 200 && !strings.Contains(bodyStr, "login") && !strings.Contains(bodyStr, "unauthorized") {
							events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
								"vuln_name":   fmt.Sprintf("Exposed Public %s Instance", check.name),
								"severity":    "high",
								"url":         check.url,
								"evidence":    bodyStr,
								"description": fmt.Sprintf("Exposed public %s instance found at %s. Access is allowed without credentials.", check.name, check.url),
							}, "high"))
						}
					}
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*CloudExposureTool)(nil)
