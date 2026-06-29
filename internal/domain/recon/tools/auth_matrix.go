package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type AuthMatrixTool struct{}

func (t *AuthMatrixTool) Name() string {
	return "auth_matrix"
}

func (t *AuthMatrixTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	sessions := scanCtx.AuthSessions
	if len(sessions) == 0 {
		slog.Debug("auth_matrix: no auth sessions configured, skipping")
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 30
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
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		}

		type sessionResult struct {
			session    recon.AuthSession
			statusCode int
			body       []byte
			contentLen int
			hasPII     bool
			err        error
		}

		results := make([]sessionResult, len(sessions))
		var wg sync.WaitGroup

		for i, sess := range sessions {
			wg.Add(1)
			go func(idx int, s recon.AuthSession) {
				defer wg.Done()
				req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
				if err != nil {
					results[idx] = sessionResult{session: s, err: err}
					return
				}
				for k, v := range scanCtx.Headers {
					req.Header.Set(k, v)
				}
				for k, v := range s.Headers {
					req.Header.Set(k, v)
				}

				resp, err := client.Do(req)
				if err != nil {
					results[idx] = sessionResult{session: s, err: err}
					return
				}
				defer resp.Body.Close()

				body, err := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
				if err != nil {
					results[idx] = sessionResult{session: s, err: err}
					return
				}

				results[idx] = sessionResult{
					session:    s,
					statusCode: resp.StatusCode,
					body:       body,
					contentLen: len(body),
					hasPII:     detectPII(body),
				}
			}(i, sess)
		}
		wg.Wait()

		var events []recon.Event

		// Compare each pair of sessions
		for i := 0; i < len(results); i++ {
			for j := i + 1; j < len(results); j++ {
				a, b := results[i], results[j]
				if a.err != nil || b.err != nil {
					continue
				}

				sim := bodySimilarity(a.body, b.body)

				// Unauthenticated vs Authenticated: broken auth
				if (a.session.Label == "none" || b.session.Label == "none") && a.statusCode == 200 && b.statusCode == 200 && sim > 0.9 {
					authLabel := a.session.Label
					if authLabel == "none" {
						authLabel = b.session.Label
					}
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":    "Broken Authentication",
						"severity":     "high",
						"comparison":   fmt.Sprintf("none vs %s", authLabel),
						"status_a":     fmt.Sprintf("%d", a.statusCode),
						"status_b":     fmt.Sprintf("%d", b.statusCode),
						"similarity":   fmt.Sprintf("%.2f", sim),
						"description":  fmt.Sprintf("Unauthenticated request returns same data as %s session (similarity: %.2f)", authLabel, sim),
					}, "high"))
					slog.Warn("Broken auth detected", "target", target, "similarity", sim)
					continue
				}

				// Cross-user comparison: IDOR
				if a.session.Label != b.session.Label && a.statusCode == 200 && b.statusCode == 200 && sim > 0.85 {
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":    "IDOR / BOLA",
						"severity":     "critical",
						"comparison":   fmt.Sprintf("%s vs %s", a.session.Label, b.session.Label),
						"status_a":     fmt.Sprintf("%d", a.statusCode),
						"status_b":     fmt.Sprintf("%d", b.statusCode),
						"similarity":   fmt.Sprintf("%.2f", sim),
						"has_pii":      fmt.Sprintf("%v", a.hasPII || b.hasPII),
						"description":  fmt.Sprintf("Cross-account data access: %s can read %s resource (similarity: %.2f)", a.session.Label, b.session.Label, sim),
					}, "critical"))
					slog.Warn("IDOR detected", "target", target, "a", a.session.Label, "b", b.session.Label, "similarity", sim)
					continue
				}

				// User vs Admin: privilege escalation
				if (isAdmin(a.session.Label) != isAdmin(b.session.Label)) && a.statusCode == 200 && b.statusCode == 200 {
					if sim > 0.7 {
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":    "Privilege Escalation",
							"severity":     "critical",
							"comparison":   fmt.Sprintf("%s vs %s", a.session.Label, b.session.Label),
							"status_a":     fmt.Sprintf("%d", a.statusCode),
							"status_b":     fmt.Sprintf("%d", b.statusCode),
							"similarity":   fmt.Sprintf("%.2f", sim),
							"description":  fmt.Sprintf("Non-admin %s gets same data as admin %s (similarity: %.2f)", nonAdminLabel(a.session.Label, b.session.Label), adminLabel(a.session.Label, b.session.Label), sim),
						}, "critical"))
						slog.Warn("Privilege escalation detected", "target", target, "similarity", sim)
					}
				}

				// User vs User with different IDs: IDOR with numeric IDs
				if a.session.Label != b.session.Label && !isAdmin(a.session.Label) && !isAdmin(b.session.Label) {
					if a.statusCode == 200 && b.statusCode == 200 && sim > 0.8 && a.hasPII {
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":    "IDOR with PII exposure",
							"severity":     "critical",
							"comparison":   fmt.Sprintf("%s vs %s", a.session.Label, b.session.Label),
							"similarity":   fmt.Sprintf("%.2f", sim),
							"has_pii":      "true",
							"description":  fmt.Sprintf("Cross-account access with PII in response: %s reads %s data", a.session.Label, b.session.Label),
						}, "critical"))
					}
				}
			}
		}

		// Baseline: unauthenticated request
		if len(results) > 0 {
			var baseline *sessionResult
			for _, r := range results {
				if r.session.Label == "none" {
					baseline = &r
					break
				}
			}
			if baseline == nil && len(results) > 0 {
				baseline = &results[0]
			}
			if baseline != nil && baseline.statusCode == 200 {
				hash := sha256.Sum256(baseline.body)
				events = append(events, recon.NewEvent(target, t.Name(), "auth_baseline", map[string]string{
					"status_code":   fmt.Sprintf("%d", baseline.statusCode),
					"content_len":   fmt.Sprintf("%d", baseline.contentLen),
					"body_hash":     fmt.Sprintf("%x", hash[:8]),
					"session_label": baseline.session.Label,
				}))
			}
		}

		return events, nil
	})
}

func bodySimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}
	aHash := sha256.Sum256(a)
	bHash := sha256.Sum256(b)
	if aHash == bHash {
		return 1.0
	}

	// Token-level Jaccard similarity
	aTokens := tokenize(a)
	bTokens := tokenize(b)
	if len(aTokens) == 0 || len(bTokens) == 0 {
		return 0.0
	}
	intersection := 0
	for t := range aTokens {
		if _, ok := bTokens[t]; ok {
			intersection++
		}
	}
	union := len(aTokens) + len(bTokens) - intersection
	if union == 0 {
		return 0.0
	}
	return float64(intersection) / float64(union)
}

func tokenize(data []byte) map[string]struct{} {
	tokens := make(map[string]struct{})
	s := string(data)
	for _, word := range strings.Fields(s) {
		w := strings.TrimSpace(word)
		if w != "" {
			tokens[w] = struct{}{}
		}
	}
	return tokens
}

func detectPII(data []byte) bool {
	s := string(data)
	piiPatterns := []string{
		"@",
		"email",
		"phone",
		"address",
		"ssn",
		"credit",
		"card",
		"birth",
		"passport",
	}
	s = strings.ToLower(s)
	for _, p := range piiPatterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func isAdmin(label string) bool {
	return strings.Contains(strings.ToLower(label), "admin")
}

func nonAdminLabel(a, b string) string {
	if isAdmin(a) {
		return b
	}
	return a
}

func adminLabel(a, b string) string {
	if isAdmin(a) {
		return a
	}
	return b
}

var _ recon.Tool = (*AuthMatrixTool)(nil)
