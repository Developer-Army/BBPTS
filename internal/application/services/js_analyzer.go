package services

import (
	"context"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"regexp"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
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
		proxy = proxies[rand.Intn(len(proxies))]
	}
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	client, _ := network.NewStealthClient(profile, proxy)
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

	// 1. Recover React/Vue/Angular router paths
	routeRe := regexp.MustCompile(`(?i)(?:path|route)\s*:\s*['"\x60](/[a-zA-Z0-9_/-]+)['"\x60]`)
	routes := routeRe.FindAllStringSubmatch(content, -1)
	for _, match := range routes {
		events = append(events, NewEvent(match[1], j.Name(), "frontend_route", map[string]string{
			"source": url,
			"type":   "router_recovery",
		}))
	}

	// 2. Recover GraphQL Mutations/Queries
	gqlRe := regexp.MustCompile(`(?i)(mutation|query)\s+([a-zA-Z0-9_]+)\s*[{(]`)
	gqlOps := gqlRe.FindAllStringSubmatch(content, -1)
	for _, match := range gqlOps {
		events = append(events, NewEvent(match[2], j.Name(), "graphql_operation", map[string]string{
			"source":  url,
			"op_type": match[1],
		}))
	}

	// 3. Recover internal API routes and JWT context
	apiRe := regexp.MustCompile(`['"\x60](/api/v[0-9]/[a-zA-Z0-9_/-]+)['"\x60]`)
	apis := apiRe.FindAllStringSubmatch(content, -1)
	for _, match := range apis {
		props := map[string]string{
			"source": url,
		}
		// Contextual heuristic: is JWT mentioned nearby?
		idx := strings.Index(content, match[1])
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
		events = append(events, NewEvent(match[1], j.Name(), "api_endpoint", props))
	}

	// 4. Scan for exposed API keys and secrets using standard patterns and entropy
	secretRegexes := map[string]*regexp.Regexp{
		"aws_key":      regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"google_api":   regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
		"slack_token":  regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
		"github_token": regexp.MustCompile(`gh[pso]_[a-zA-Z0-9]{36}`),
		"stripe_key":   regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
	}

	for keyType, re := range secretRegexes {
		matches := re.FindAllString(content, -1)
		for _, secretVal := range matches {
			if computeEntropy(secretVal) > 3.0 {
				events = append(events, NewEvent(url, j.Name(), "vulnerability", map[string]string{
					"severity":  "high",
					"vuln_name": "Exposed " + keyType,
					"evidence":  "Found secret match: " + secretVal,
				}))
			}
		}
	}

	return events
}

func computeEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}
	var entropy float64
	for _, count := range counts {
		p := float64(count) / float64(len(s))
		entropy -= p * math.Log2(p)
	}
	return entropy
}
