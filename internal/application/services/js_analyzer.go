package services

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"golang.org/x/time/rate"
)

// JSAnalyzer parses JavaScript files to recover routing, mutations, and internal APIs.
type JSAnalyzer struct{}

func (j *JSAnalyzer) Name() string {
	return "js_analyzer"
}

func (j *JSAnalyzer) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var jsTargets []string
	for _, t := range targets {
		if strings.HasSuffix(t, ".js") || strings.Contains(t, ".js?") {
			jsTargets = append(jsTargets, t)
		}
	}
	if len(jsTargets) == 0 {
		return nil, nil
	}

	proxies := GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[len(proxies)-1]
	}
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	// We can use random or fallback for proxy
	_ = proxy
	client, _ := network.NewStealthClient(profile, "")
	if len(proxies) > 0 {
		// Rebuild client with proxy
		client, _ = network.NewStealthClient(profile, proxies[0])
	}
	if client != nil {
		client.SetCustomHeaders(HeadersFromCtx(ctx))
	}

	rateLimit := ToolRateLimitFromCtx(ctx, j.Name())
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, jsTargets, func(ctx context.Context, url string) ([]Event, error) {
		events := j.analyzeJS(ctx, client, url)
		return events, nil
	})
}

func (j *JSAnalyzer) analyzeJS(ctx context.Context, client *network.StealthClient, url string) []Event {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("failed to fetch JS", "url", url, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	content := string(bodyBytes)

	var events []Event

	// 1. GraphQL operation names (regex fallback)
	gqlRe := regexp.MustCompile(`(?i)(mutation|query)\s+([a-zA-Z0-9_]+)\s*[{(]`)
	gqlOps := gqlRe.FindAllStringSubmatch(content, -1)
	for _, match := range gqlOps {
		events = append(events, NewEvent(match[2], j.Name(), "graphql_operation", map[string]string{
			"source":  url,
			"op_type": match[1],
		}))
	}

	// 2. Delegate to domain JSAnalyzer
	domainAnalyzer := recon.NewJSAnalyzer()
	domainAnalyzer.SetHTTPClient(client)
	findings := domainAnalyzer.AnalyzeContent(url, content)

	// --- Differential JS Change Detection ---
	store := storage.FromContext(ctx)
	if store != nil {
		h := sha256.New()
		h.Write(bodyBytes)
		currentHash := fmt.Sprintf("%x", h.Sum(nil))

		prevEv, err := store.GetEvidenceModel(url)
		if err == nil && prevEv != nil && prevEv.Hash != currentHash {
			oldFindings := domainAnalyzer.AnalyzeContent(url, string(prevEv.RawData))
			diffText := diffFindings(oldFindings, findings)
			if diffText != "" {
				events = append(events, NewEventWithSeverity(url, j.Name(), "vulnerability", map[string]string{
					"vuln_name":   "JavaScript File Changed (New Attack Surface)",
					"severity":    "high",
					"evidence":    diffText,
					"description": "JS file content changed since last crawl. Diff:\n" + diffText,
				}, "high"))
				slog.Warn("JS file changed with new attack surface", "url", url)
			}
		}
		_ = store.SaveEvidence(url, extractHost(url), j.Name(), 1.0, bodyBytes, currentHash)
	}

	for _, f := range findings {
		switch f.Type {
		case "secret", "entropy":
			severity := f.Severity
			if severity == "" {
				severity = "high"
			}
			vulnName := "Exposed " + f.Name
			nameLower := strings.ToLower(f.Name)
			if strings.Contains(nameLower, "aws") {
				vulnName += " (aws_key)"
			} else if strings.Contains(nameLower, "slack") {
				vulnName += " (slack_token)"
			} else if strings.Contains(nameLower, "google") {
				vulnName += " (google_api)"
			} else if strings.Contains(nameLower, "github") {
				vulnName += " (github_token)"
			} else if strings.Contains(nameLower, "stripe") {
				vulnName += " (stripe_key)"
			}
			events = append(events, NewEvent(url, j.Name(), "vulnerability", map[string]string{
				"severity":  severity,
				"vuln_name": vulnName,
				"evidence":  "Found secret match: " + f.Value,
			}))
		case "endpoint", "semantic_endpoint":
			props := map[string]string{
				"source": url,
			}
			idx := strings.Index(content, f.Value)
			if idx != -1 {
				start := idx - 200
				if start < 0 {
					start = 0
				}
				end := idx + 200
				if end > len(content) {
					end = len(content)
				}
				window := content[start:end]
				if strings.Contains(strings.ToLower(window), "jwt") || strings.Contains(strings.ToLower(window), "bearer") || strings.Contains(strings.ToLower(window), "admin") {
					props["context"] = "auth_required or admin_context"
				}
			}
			events = append(events, NewEvent(f.Value, j.Name(), "api_endpoint", props))

			// Also emit a frontend_route if AST router definition
			if f.Type == "semantic_endpoint" && strings.Contains(f.Name, "Route:") {
				events = append(events, NewEvent(f.Value, j.Name(), "frontend_route", map[string]string{
					"source": url,
					"type":   "router_recovery",
				}))
			}
		case "framework", "lazy_route", "sourcemap":
			events = append(events, NewEvent(url, j.Name(), "discovery", map[string]string{
				"source": url,
				"detail": f.Name + ": " + f.Value,
				"type":   f.Type,
			}))
		}
	}

	return events
}

func diffFindings(oldFindings, newFindings []recon.JSFinding) string {
	oldMap := make(map[string]bool)
	for _, f := range oldFindings {
		key := f.Type + ":" + f.Value
		oldMap[key] = true
	}

	var newEndpoints []string
	var newSecrets []string

	for _, f := range newFindings {
		key := f.Type + ":" + f.Value
		if !oldMap[key] {
			if f.Type == "endpoint" || f.Type == "semantic_endpoint" {
				newEndpoints = append(newEndpoints, f.Value)
			} else if f.Type == "secret" || f.Type == "entropy" {
				newSecrets = append(newSecrets, fmt.Sprintf("%s (%s)", f.Name, f.Value))
			}
		}
	}

	var parts []string
	if len(newEndpoints) > 0 {
		parts = append(parts, "New Endpoints:\n- " + strings.Join(newEndpoints, "\n- "))
	}
	if len(newSecrets) > 0 {
		parts = append(parts, "New Secrets:\n- " + strings.Join(newSecrets, "\n- "))
	}

	return strings.Join(parts, "\n\n")
}
