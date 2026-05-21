// Package recon provides reconnaissance domain logic
package recon

import (
	"context"
	"crypto/sha256"
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

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
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
	httpClient    *http.Client
	maxFileSize   int64
	semanticCache map[string][]SemanticRoute // cache AST results per JS hash
	mu            sync.RWMutex
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
		maxFileSize:   5 * 1024 * 1024, // 5MB max
		semanticCache: make(map[string][]SemanticRoute),
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

	// 1. Compute content hash for dedup/diff
	contentHash := computeContentHash(body)

	// 2. Regex-based endpoint extraction (fast, high recall)
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

	// 3. AST-based semantic endpoint extraction (higher precision, detects dynamic routes)
	a.mu.RLock()
	cachedRoutes, ok := a.semanticCache[contentHash]
	a.mu.RUnlock()

	if !ok {
		// Parse AST and extract semantic routes
		routes := a.analyzeASTSemantic(body)
		cachedRoutes = routes
		// Cache for later reuse
		a.mu.Lock()
		a.semanticCache[contentHash] = routes
		if len(a.semanticCache) > 1000 {
			// LRU-style prune: keep most recent 1000 hashes
			// (in production use a proper LRU cache)
			for k := range a.semanticCache {
				delete(a.semanticCache, k)
				break
			}
		}
		a.mu.Unlock()
	}

	for _, route := range cachedRoutes {
		findings = append(findings, JSFinding{
			SourceURL: jsURL,
			Type:      "semantic_endpoint",
			Name:      fmt.Sprintf("Route: %s %s", route.Method, route.Path),
			Value:     route.Path,
			Severity:  routeSeverity(route),
		})
	}

	// 4. Scan for known secret patterns
	secrets := scanSecrets(body, jsURL)
	findings = append(findings, secrets...)

	// 5. Entropy analysis for unknown secrets
	entropyFindings := scanEntropy(body, jsURL)
	findings = append(findings, entropyFindings...)

	// 6. Detect framework-specific patterns (React Router, Vue Router, Angular)
	frameworkFindings := a.detectFrameworkPatterns(body, jsURL)
	findings = append(findings, frameworkFindings...)

	if len(findings) > 0 {
		slog.Debug("js analyzer: findings",
			"url", jsURL,
			"endpoints", len(endpoints),
			"semantic_routes", len(cachedRoutes),
			"secrets", len(secrets),
			"entropy", len(entropyFindings),
			"framework", len(frameworkFindings),
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

// computeContentHash returns SHA256 of JS body for dedup/cache key.
func computeContentHash(body string) string {
	h := sha256.New()
	h.Write([]byte(body))
	return fmt.Sprintf("%x", h.Sum(nil)[:16]) // 128-bit hash
}

// analyzeASTSemantic parses JavaScript AST to extract structured routes and API calls.
func (a *JSAnalyzer) analyzeASTSemantic(body string) []SemanticRoute {
	var routes []SemanticRoute

	// Parse with goja/parser (supports modern JS syntax)
	program, err := parser.ParseFile(nil, "bundle.js", body, 0, parser.WithDisableSourceMaps)
	if err != nil {
		// Fallback to simpler regex if AST fails (minified/obfuscated)
		slog.Debug("AST parse failed, skipping semantic analysis", "error", err)
		return routes
	}

	// Walk AST
	walkJSAST(program, func(n ast.Node) {
		a.extractRoutesFromNode(n, &routes, "bundle.js")
	})

	return routes
}

// extractRoutesFromNode visits a single AST node looking for route-defining patterns.
func (a *JSAnalyzer) extractRoutesFromNode(node ast.Node, routes *[]SemanticRoute, file string) {
	switch n := node.(type) {
	case *ast.CallExpression:
		a.extractFetchCalls(n, routes, file)
		a.extractRouterDefinitions(n, routes, file)
		a.extractGraphQLOperations(n, routes, file)

	case *ast.ObjectLiteral:
		a.extractRouteObjects(n, routes, file)

	case *ast.AssignExpression:
		a.extractVariableAssignments(n, routes, file)

	case *ast.NewExpression:
		// Detect: new Router(), new ApiClient(), etc.
		if ident, ok := n.Callee.(*ast.Identifier); ok {
			className := ident.Name.String()
			if len(n.ArgumentList) > 0 {
				if objLit, ok := n.ArgumentList[0].(*ast.ObjectLiteral); ok {
					for _, prop := range objLit.Value {
						if keyed, ok := prop.(*ast.PropertyKeyed); ok {
							if propertyKeyName(keyed.Key) == "routes" {
								if arr, ok := keyed.Value.(*ast.ArrayLiteral); ok {
									for _, item := range arr.Value {
										if obj, ok := item.(*ast.ObjectLiteral); ok {
											a.extractRouteObjectFromConfig(obj, routes, file, className)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

func (a *JSAnalyzer) extractFetchCalls(call *ast.CallExpression, routes *[]SemanticRoute, file string) {
	if ident, ok := call.Callee.(*ast.Identifier); ok {
		method := "GET"
		if ident.Name == "fetch" && len(call.ArgumentList) >= 1 {
			// Check for method option in second arg
			if len(call.ArgumentList) >= 2 {
				if options, ok := call.ArgumentList[1].(*ast.ObjectLiteral); ok {
					for _, prop := range options.Value {
						if keyed, ok := prop.(*ast.PropertyKeyed); ok && propertyKeyName(keyed.Key) == "method" {
							if str, ok := keyed.Value.(*ast.StringLiteral); ok {
								method = strings.ToUpper(stringLiteralValue(str))
							}
						}
					}
				}
			}
			if str, ok := call.ArgumentList[0].(*ast.StringLiteral); ok {
				path := stringLiteralValue(str)
				*routes = append(*routes, SemanticRoute{
					Path:       path,
					Method:     method,
					IsGraphQL:  strings.Contains(path, "graphql"),
					SourceFile: file,
				})
			}
		}
	}
}

func (a *JSAnalyzer) extractRouterDefinitions(call *ast.CallExpression, routes *[]SemanticRoute, file string) {
	// Detect: router.get('/path', ...), router.post('/path', ...)
	if member, ok := call.Callee.(*ast.DotExpression); ok {
		method := strings.ToUpper(member.Identifier.Name.String())
		if method == "GET" || method == "POST" || method == "PUT" || method == "DELETE" || method == "PATCH" {
			if len(call.ArgumentList) >= 1 {
				if str, ok := call.ArgumentList[0].(*ast.StringLiteral); ok {
					*routes = append(*routes, SemanticRoute{
						Path:       stringLiteralValue(str),
						Method:     method,
						SourceFile: file,
					})
				}
			}
		}
	}
}

func (a *JSAnalyzer) extractGraphQLOperations(call *ast.CallExpression, routes *[]SemanticRoute, file string) {
	// Detect: client.query({ query: gql`...` }) or fetch('/graphql', ...)
	if ident, ok := call.Callee.(*ast.Identifier); ok {
		if ident.Name == "gql" || ident.Name == "graphql" {
			// Tag as GraphQL operation
			*routes = append(*routes, SemanticRoute{
				Path:       "/graphql",
				Method:     "POST",
				IsGraphQL:  true,
				SourceFile: file,
			})
		}
	}
}

func (a *JSAnalyzer) extractRouteObjects(objLit *ast.ObjectLiteral, routes *[]SemanticRoute, file string) {
	for _, prop := range objLit.Value {
		if keyed, ok := prop.(*ast.PropertyKeyed); ok {
			if propertyKeyName(keyed.Key) == "path" {
				if str, ok := keyed.Value.(*ast.StringLiteral); ok {
					*routes = append(*routes, SemanticRoute{
						Path:       stringLiteralValue(str),
						Method:     "GET",
						SourceFile: file,
					})
				}
			}
		}
	}
}

func (a *JSAnalyzer) extractRouteObjectFromConfig(objLit *ast.ObjectLiteral, routes *[]SemanticRoute, file, className string) {
	var path, method string
	for _, prop := range objLit.Value {
		if keyed, ok := prop.(*ast.PropertyKeyed); ok {
			switch propertyKeyName(keyed.Key) {
			case "path":
				if str, ok := keyed.Value.(*ast.StringLiteral); ok {
					path = stringLiteralValue(str)
				}
			case "method":
				if str, ok := keyed.Value.(*ast.StringLiteral); ok {
					method = strings.ToUpper(stringLiteralValue(str))
				}
			}
		}
	}
	if path != "" {
		*routes = append(*routes, SemanticRoute{
			Path:       path,
			Method:     method,
			SourceFile: file,
		})
	}
}

func (a *JSAnalyzer) extractVariableAssignments(assign *ast.AssignExpression, routes *[]SemanticRoute, file string) {
	// Detect: const apiUrl = '/api/v1/users';
	if right, ok := assign.Right.(*ast.StringLiteral); ok {
		val := stringLiteralValue(right)
		// Check if the assigned value looks like an endpoint
		if strings.HasPrefix(val, "/") && (strings.Contains(val, "/api") || strings.Contains(val, "/v") || strings.Contains(val, "graphql")) {
			*routes = append(*routes, SemanticRoute{
				Path:       val,
				Method:     "UNKNOWN",
				Variable:   fmt.Sprintf("%s", assign.Left),
				SourceFile: file,
			})
		}
	}
}

func (a *JSAnalyzer) detectFrameworkPatterns(body string, jsURL string) []JSFinding {
	var findings []JSFinding
	bodyLower := strings.ToLower(body)

	frameworkSignatures := map[string]struct {
		tag    string
		reason string
		score  int
	}{
		"react":    {"react", "React framework detected (JSX hints)", 3},
		"vue":      {"vue", "Vue.js framework detected", 3},
		"angular":  {"angular", "Angular framework detected", 3},
		"next.js":  {"nextjs", "Next.js SSR framework detected", 5},
		"nuxt.js":  {"nuxtjs", "Nuxt.js SSR framework detected", 5},
		"ember.js": {"ember", "Ember.js SPA framework detected", 3},
		"svelte":   {"svelte", "Svelte framework detected", 3},
		"gatsby":   {"gatsby", "Gatsby static site generator", 2},
	}

	for fw, sig := range frameworkSignatures {
		if strings.Contains(bodyLower, fw) {
			findings = append(findings, JSFinding{
				SourceURL: jsURL,
				Type:      "framework",
				Name:      "Framework Detected",
				Value:     sig.tag,
				Severity:  "info",
			})
		}
	}

	// Detect lazy-loaded routes (code-splitting patterns)
	if strings.Contains(bodyLower, "import()") || strings.Contains(bodyLower, "require.ensure") {
		findings = append(findings, JSFinding{
			SourceURL: jsURL,
			Type:      "lazy_route",
			Name:      "Dynamic Import (Lazy Route)",
			Value:     "possible lazy-loaded route or chunk",
			Severity:  "low",
		})
	}

	// Detect source map URL (reveals original structure)
	if strings.Contains(bodyLower, "//# sourceMappingURL=") || strings.Contains(bodyLower, "sourceMappingURL=") {
		findings = append(findings, JSFinding{
			SourceURL: jsURL,
			Type:      "sourcemap",
			Name:      "Source Map Available",
			Value:     "original source structure may be recoverable",
			Severity:  "low",
		})
	}

	return findings
}

// routeSeverity estimates attack surface value of a route.
func routeSeverity(route SemanticRoute) string {
	if route.IsGraphQL {
		return "high"
	}
	if route.IsAuthFlow {
		return "high"
	}
	if strings.Contains(route.Path, "admin") || strings.Contains(route.Path, "api") || strings.Contains(route.Path, "login") {
		return "medium"
	}
	return "low"
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
