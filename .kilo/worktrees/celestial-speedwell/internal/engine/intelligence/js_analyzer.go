// Package intelligence — js_analyzer.go provides deep JavaScript analysis
// capabilities: endpoint extraction, secret detection, and entropy analysis.
// This module processes URLs found by crawlers (katana, waybackurls, gau) to
// extract hidden API endpoints and hardcoded credentials from JS bundles.
package intelligence

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// JSFinding represents a single finding from JavaScript analysis.
type JSFinding struct {
	SourceURL string `json:"source_url"`
	Type      string `json:"type"` // "endpoint", "secret", "entropy"
	Name      string `json:"name"`
	Value     string `json:"value"`
	Severity  string `json:"severity"`
	Line      int    `json:"line,omitempty"`
}

// JSAnalyzer fetches and analyzes JavaScript files for hidden endpoints and secrets.
type JSAnalyzer struct {
	httpClient  *http.Client
	maxFileSize int64
}

// NewJSAnalyzer creates a JSAnalyzer with sensible defaults.
func NewJSAnalyzer() *JSAnalyzer {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext: (&net.Dialer{
			Timeout: 8 * time.Second,
		}).DialContext,
	}
	return &JSAnalyzer{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		maxFileSize: 5 * 1024 * 1024, // 5MB max
	}
}

// Endpoint extraction patterns — these find API routes, paths, and URLs
// embedded in JavaScript source code.
var endpointPatterns = []*regexp.Regexp{
	// Absolute paths to API endpoints
	regexp.MustCompile(`['"](/api/[a-zA-Z0-9_/\-{}:.]+)['"]`),
	regexp.MustCompile(`['"](/v[0-9]+/[a-zA-Z0-9_/\-{}:.]+)['"]`),
	regexp.MustCompile(`['"](/graphql[a-zA-Z0-9_/\-{}:.]*?)['"]`),

	// Relative endpoints
	regexp.MustCompile(`['"]([a-zA-Z0-9_\-]+/[a-zA-Z0-9_/\-{}:.]+)['"]`),

	// Full URLs in code
	regexp.MustCompile(`['"]https?://[a-zA-Z0-9.\-]+(?::[0-9]+)?/[a-zA-Z0-9_/\-{}:.?&=]+['"]`),

	// Fetch/XHR patterns
	regexp.MustCompile(`(?:fetch|axios|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"]([^'"]+)['"]`),

	// Template literal URLs
	regexp.MustCompile("`" + `(https?://[^` + "`" + `]+)` + "`"),

	// window.location / document.location assignments
	regexp.MustCompile(`(?:window|document)\.location\s*=\s*['"]([^'"]+)['"]`),

	// React Router / Vue Router paths
	regexp.MustCompile(`path\s*:\s*['"]([/][a-zA-Z0-9_/\-{}:.]+)['"]`),
}

// AnalyzeAll processes multiple JS URLs concurrently.
func (a *JSAnalyzer) AnalyzeAll(ctx context.Context, urls []string, concurrency int) []JSFinding {
	if concurrency <= 0 {
		concurrency = 10
	}

	// Filter to only JS URLs
	jsURLs := filterJSURLs(urls)
	if len(jsURLs) == 0 {
		return nil
	}

	slog.Info("js analyzer: starting", "js_files", len(jsURLs))

	jobs := make(chan string, len(jsURLs))
	results := make(chan []JSFinding, len(jsURLs))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				findings := a.AnalyzeURL(ctx, url)
				if len(findings) > 0 {
					results <- findings
				}
			}
		}()
	}

	for _, u := range jsURLs {
		jobs <- u
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	var allFindings []JSFinding
	for batch := range results {
		allFindings = append(allFindings, batch...)
	}

	// Sort by severity
	severityOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(allFindings, func(i, j int) bool {
		return severityOrder[allFindings[i].Severity] < severityOrder[allFindings[j].Severity]
	})

	slog.Info("js analyzer: complete",
		"js_files_analyzed", len(jsURLs),
		"findings", len(allFindings),
	)

	return allFindings
}

// AnalyzeURL fetches a single JS file and extracts endpoints and secrets.
func (a *JSAnalyzer) AnalyzeURL(ctx context.Context, jsURL string) []JSFinding {
	body, err := a.fetchJS(ctx, jsURL)
	if err != nil {
		slog.Debug("js analyzer: fetch failed", "url", jsURL, "error", err)
		return nil
	}

	var findings []JSFinding

	// 1. Extract endpoints
	endpoints := extractEndpoints(body)
	for _, ep := range endpoints {
		findings = append(findings, JSFinding{
			SourceURL: jsURL,
			Type:      "endpoint",
			Name:      "Hidden Endpoint",
			Value:     ep,
			Severity:  "medium",
		})
	}

	// 2. Scan for known secret patterns
	secrets := scanSecrets(body, jsURL)
	findings = append(findings, secrets...)

	// 3. Entropy analysis for unknown secrets
	entropyFindings := scanEntropy(body, jsURL)
	findings = append(findings, entropyFindings...)

	if len(findings) > 0 {
		slog.Debug("js analyzer: findings",
			"url", jsURL,
			"endpoints", len(endpoints),
			"secrets", len(secrets),
			"entropy", len(entropyFindings),
		)
	}

	return findings
}

// fetchJS downloads JavaScript content with size limits.
func (a *JSAnalyzer) fetchJS(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BBPTS/1.0)")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, a.maxFileSize))
	if err != nil {
		return "", err
	}

	return string(body), nil
}

// extractEndpoints finds API endpoints and paths in JavaScript source.
func extractEndpoints(jsBody string) []string {
	seen := make(map[string]struct{})
	var endpoints []string

	for _, pattern := range endpointPatterns {
		matches := pattern.FindAllStringSubmatch(jsBody, -1)
		for _, match := range matches {
			if len(match) < 2 {
				continue
			}
			ep := strings.Trim(match[1], `'"`)
			ep = strings.TrimSpace(ep)

			// Filter out noise
			if isNoiseEndpoint(ep) {
				continue
			}

			if _, ok := seen[ep]; ok {
				continue
			}
			seen[ep] = struct{}{}
			endpoints = append(endpoints, ep)
		}
	}

	return endpoints
}

// scanSecrets checks JS body against all known secret patterns.
func scanSecrets(jsBody string, sourceURL string) []JSFinding {
	var findings []JSFinding

	for _, sp := range SecretPatterns {
		matches := sp.Pattern.FindAllString(jsBody, 5) // Cap at 5 per pattern
		for _, match := range matches {
			findings = append(findings, JSFinding{
				SourceURL: sourceURL,
				Type:      "secret",
				Name:      sp.Name,
				Value:     truncate(match, 120),
				Severity:  sp.Severity,
			})
		}
	}

	return findings
}

// scanEntropy performs Shannon entropy analysis to find high-entropy strings
// that could be undiscovered secrets (API keys, tokens, etc).
func scanEntropy(jsBody string, sourceURL string) []JSFinding {
	var findings []JSFinding

	// Extract string literals and check entropy
	stringPattern := regexp.MustCompile(`['"]([A-Za-z0-9+/=_\-]{20,})['"]`)
	matches := stringPattern.FindAllStringSubmatch(jsBody, 100) // Cap scan

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := match[1]

		// Skip common false positives
		if isCommonFalsePositive(value) {
			continue
		}

		entropy := shannonEntropy(value)
		// High-entropy threshold (typical for base64-encoded keys)
		if entropy > 4.5 && len(value) >= 24 {
			findings = append(findings, JSFinding{
				SourceURL: sourceURL,
				Type:      "entropy",
				Name:      fmt.Sprintf("High-Entropy String (%.2f bits)", entropy),
				Value:     truncate(value, 80),
				Severity:  "medium",
			})
		}
	}

	return findings
}

// shannonEntropy calculates the Shannon entropy of a string.
// Higher entropy = more randomness = more likely to be a secret.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	length := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

// filterJSURLs returns only URLs that look like JavaScript files.
func filterJSURLs(urls []string) []string {
	var jsURLs []string
	for _, u := range urls {
		lower := strings.ToLower(u)
		if strings.HasSuffix(lower, ".js") ||
			strings.Contains(lower, ".js?") ||
			strings.Contains(lower, "/js/") ||
			strings.Contains(lower, "javascript") ||
			strings.HasSuffix(lower, ".mjs") {
			if strings.HasPrefix(lower, "http") {
				jsURLs = append(jsURLs, u)
			}
		}
	}
	return jsURLs
}

// isNoiseEndpoint filters out common false positives in endpoint extraction.
func isNoiseEndpoint(ep string) bool {
	if len(ep) < 3 || len(ep) > 200 {
		return true
	}

	// Filter static asset paths
	noisePatterns := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".map", "webpack", "node_modules", "__webpack",
		"polyfill", "sourcemap", "chunk-", "vendor",
	}
	lower := strings.ToLower(ep)
	for _, n := range noisePatterns {
		if strings.Contains(lower, n) {
			return true
		}
	}

	return false
}

// isCommonFalsePositive filters entropy false positives.
func isCommonFalsePositive(s string) bool {
	lower := strings.ToLower(s)
	// Common base64-encoded content that isn't a secret
	falsePositives := []string{
		"abcdefghijklmnopqrstuvwxyz",
		"qwertyuiopasdfghjklzxcvbnm",
		"aaaaaaaaaaaa",
	}
	for _, fp := range falsePositives {
		if strings.Contains(lower, fp) {
			return true
		}
	}
	// Skip if it's all the same character repeated
	if len(s) > 0 {
		allSame := true
		first := s[0]
		for i := 1; i < len(s); i++ {
			if s[i] != first {
				allSame = false
				break
			}
		}
		if allSame {
			return true
		}
	}
	return false
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
