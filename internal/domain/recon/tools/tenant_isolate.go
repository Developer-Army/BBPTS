package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type TenantIsolateTool struct{}

func (t *TenantIsolateTool) Name() string {
	return "tenant_isolate"
}

func (t *TenantIsolateTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	sessions := scanCtx.AuthSessions
	if len(sessions) < 2 {
		slog.Debug("tenant_isolate: need at least 2 auth sessions for cross-tenant testing")
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
		var events []recon.Event

		if !t.detectsMultiTenancy(ctx, client, target, scanCtx.Headers) {
			return nil, nil
		}

		slog.Info("Multi-tenant target detected, testing cross-tenant isolation", "target", target)

		// Get resources from each tenant session
		type tenantResources struct {
			session   recon.AuthSession
			resources []string
			responses map[string][]byte
		}

		var tenantData []*tenantResources
		var mu sync.Mutex
		var wg sync.WaitGroup

		for _, sess := range sessions {
			wg.Add(1)
			go func(s recon.AuthSession) {
				defer wg.Done()
				resources := t.discoverResources(ctx, client, target, s, scanCtx.Headers)
				mu.Lock()
				tenantData = append(tenantData, &tenantResources{
					session:   s,
					resources: resources,
					responses: make(map[string][]byte),
				})
				mu.Unlock()
			}(sess)
		}
		wg.Wait()

		for i, tenantA := range tenantData {
			for j, tenantB := range tenantData {
				if i == j {
					continue
				}

				for _, resourceURL := range tenantA.resources {

					status, body := t.doRequest(ctx, client, resourceURL, tenantB.session, scanCtx.Headers)
					if status == 0 {
						continue
					}

					if status == 200 && len(body) > 0 {

						statusA, bodyA := t.doRequest(ctx, client, resourceURL, tenantA.session, scanCtx.Headers)
						if statusA == 200 {
							sim := bodySimilarity(body, bodyA)
							if sim > 0.7 {
								events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
									"vuln_name":   "Cross-Tenant Data Access",
									"severity":    "critical",
									"resource":    resourceURL,
									"tenant_a":    tenantA.session.Label,
									"tenant_b":    tenantB.session.Label,
									"similarity":  fmt.Sprintf("%.2f", sim),
									"description": fmt.Sprintf("Tenant '%s' can access tenant '%s' resource at %s (similarity: %.2f)", tenantB.session.Label, tenantA.session.Label, resourceURL, sim),
								}, "critical"))
								slog.Warn("Cross-tenant access detected", "target", target, "resource", resourceURL, "from", tenantB.session.Label, "to", tenantA.session.Label)
							}
						}
					}
				}
			}
		}

		return events, nil
	})
}

func (t *TenantIsolateTool) detectsMultiTenancy(ctx context.Context, client *http.Client, target string, headers map[string]string) bool {
	indicators := []string{
		"tenant", "org", "organization", "workspace", "team",
		"account", "company", "client", "customer",
	}

	status, body := t.doGET(ctx, client, target, headers)
	if status == 0 {
		return false
	}

	bodyStr := strings.ToLower(string(body))
	for _, ind := range indicators {
		if strings.Contains(bodyStr, ind) {
			return true
		}
	}

	if strings.Contains(target, "tenant") || strings.Contains(target, "org_") || strings.Contains(target, "/org/") {
		return true
	}

	return false
}

func (t *TenantIsolateTool) discoverResources(ctx context.Context, client *http.Client, target string, sess recon.AuthSession, headers map[string]string) []string {
	var resources []string

	apiPaths := []string{
		"/api/users/me",
		"/api/profile",
		"/api/settings",
		"/api/documents",
		"/api/files",
		"/api/messages",
		"/api/notifications",
		"/api/billing",
		"/api/team",
		"/api/projects",
	}

	base := strings.TrimSuffix(target, "/")
	for _, path := range apiPaths {
		url := base + path
		status, body := t.doRequest(ctx, client, url, sess, headers)
		if status == 200 && len(body) > 0 {
			resources = append(resources, url)

			ids := extractIDs(body)
			for _, id := range ids {

				for _, pattern := range []string{
					fmt.Sprintf("/api/users/%s", id),
					fmt.Sprintf("/api/documents/%s", id),
					fmt.Sprintf("/api/files/%s", id),
				} {
					testURL := base + pattern
					status, _ := t.doRequest(ctx, client, testURL, sess, headers)
					if status == 200 {
						resources = append(resources, testURL)
					}
				}
			}
		}
	}

	return resources
}

func (t *TenantIsolateTool) doRequest(ctx context.Context, client *http.Client, url string, sess recon.AuthSession, headers map[string]string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, nil
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for k, v := range sess.Headers {
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

func (t *TenantIsolateTool) doGET(ctx context.Context, client *http.Client, url string, headers map[string]string) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	return resp.StatusCode, body
}

func extractIDs(body []byte) []string {
	s := string(body)
	var ids []string

	patterns := []string{
		`"id":\s*(\d+)`,
		`"id":\s*"([^"]+)"`,
		`"user_id":\s*(\d+)`,
		`"document_id":\s*"([^"]+)"`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(s, 5)
		for _, match := range matches {
			if len(match) > 1 {
				ids = append(ids, match[1])
			}
		}
	}

	return ids
}

var _ recon.Tool = (*TenantIsolateTool)(nil)
