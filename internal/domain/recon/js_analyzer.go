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

	"github.com/Developer-Army/BBPTS/internal/domain/security"
)

type JSFinding struct {
	SourceURL string `json:"source_url"`
	Type      string `json:"type"` // "endpoint", "secret", "entropy"
	Name      string `json:"name"`
	Value     string `json:"value"`
	Severity  string `json:"severity"`
	Line      int    `json:"line,omitempty"`
}

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type JSAnalyzer struct {
	httpClient    HTTPClient
	maxFileSize   int64
	semanticCache map[string][]SemanticRoute // cache AST results per JS hash
	mu            sync.RWMutex
}

func (a *JSAnalyzer) SetHTTPClient(client HTTPClient) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.httpClient = client
}

func NewJSAnalyzer() *JSAnalyzer {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			pinnedAddr, _, err := security.ResolveAndValidateAddr(ctx, addr)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{Timeout: 8 * time.Second}
			return dialer.DialContext(ctx, network, pinnedAddr)
		},
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		pinnedAddr, host, err := security.ResolveAndValidateAddr(ctx, addr)
		if err != nil {
			return nil, err
		}
		skipVerify := false
		if val := ctx.Value("insecure"); val != nil {
			if b, ok := val.(bool); ok {
				skipVerify = b
			}
		}
		dialer := &net.Dialer{Timeout: 8 * time.Second}
		return tls.DialWithDialer(dialer, network, pinnedAddr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipVerify,
		})
	}
	return &JSAnalyzer{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
		},
		maxFileSize:   5 * 1024 * 1024,
		semanticCache: make(map[string][]SemanticRoute),
	}
}

var endpointPatterns = []*regexp.Regexp{

	regexp.MustCompile(`['"](/api/[a-zA-Z0-9_/\-{}:.]+)['"]`),
	regexp.MustCompile(`['"](/v[0-9]+/[a-zA-Z0-9_/\-{}:.]+)['"]`),
	regexp.MustCompile(`['"](/graphql[a-zA-Z0-9_/\-{}:.]*?)['"]`),

	regexp.MustCompile(`['"]([a-zA-Z0-9_\-]{2,}/[a-zA-Z0-9_/\-{}:.]{2,})['"]`),

	regexp.MustCompile(`['"]https?://[a-zA-Z0-9.\-]+(?::[0-9]+)?/[a-zA-Z0-9_/\-{}:.?&=]+['"]`),

	regexp.MustCompile(`(?:fetch|axios|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"]([^'"]+)['"]`),

	regexp.MustCompile("`" + `(https?://[^` + "`" + `]+)` + "`"),

	regexp.MustCompile(`(?:window|document)\.location\s*=\s*['"]([^'"]+)['"]`),

	regexp.MustCompile(`path\s*:\s*['"]([/][a-zA-Z0-9_/\-{}:.]+)['"]`),
}

func (a *JSAnalyzer) AnalyzeAll(ctx context.Context, urls []string, concurrency int) []JSFinding {
	if concurrency <= 0 {
		concurrency = 10
	}

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

func (a *JSAnalyzer) AnalyzeURL(ctx context.Context, jsURL string) []JSFinding {
	body, err := a.fetchJS(ctx, jsURL)
	if err != nil {
		slog.Debug("js analyzer: fetch failed", "url", jsURL, "error", err)
		return nil
	}
	return a.AnalyzeContent(jsURL, body)
}

func (a *JSAnalyzer) AnalyzeContent(jsURL string, body string) []JSFinding {
	var findings []JSFinding

	contentHash := computeContentHash(body)

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

	a.mu.RLock()
	cachedRoutes, ok := a.semanticCache[contentHash]
	a.mu.RUnlock()

	if !ok {

		routes := a.analyzeASTSemantic(body)
		cachedRoutes = routes

		a.mu.Lock()
		a.semanticCache[contentHash] = routes
		if len(a.semanticCache) > 1000 {

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

	secrets := scanSecrets(body, jsURL)
	findings = append(findings, secrets...)

	entropyFindings := scanEntropy(body, jsURL)
	findings = append(findings, entropyFindings...)

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

func computeContentHash(body string) string {
	h := sha256.New()
	h.Write([]byte(body))
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

func (a *JSAnalyzer) analyzeASTSemantic(body string) []SemanticRoute {
	var routes []SemanticRoute

	program, err := parser.ParseFile(nil, "bundle.js", body, 0, parser.WithDisableSourceMaps)
	if err != nil {

		slog.Debug("AST parse failed, skipping semantic analysis", "error", err)
		return routes
	}

	walkJSAST(program, func(n ast.Node) {
		a.extractRoutesFromNode(n, &routes, "bundle.js")
	})

	return routes
}

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

		if _, ok := n.Callee.(*ast.Identifier); ok {
			if len(n.ArgumentList) > 0 {
				if objLit, ok := n.ArgumentList[0].(*ast.ObjectLiteral); ok {
					for _, prop := range objLit.Value {
						if keyed, ok := prop.(*ast.PropertyKeyed); ok {
							if propertyKeyName(keyed.Key) == "routes" {
								if arr, ok := keyed.Value.(*ast.ArrayLiteral); ok {
									for _, item := range arr.Value {
										if obj, ok := item.(*ast.ObjectLiteral); ok {
											a.extractRouteObjectFromConfig(obj, routes, file)
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

	if ident, ok := call.Callee.(*ast.Identifier); ok {
		if ident.Name == "gql" || ident.Name == "graphql" {

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

func (a *JSAnalyzer) extractRouteObjectFromConfig(objLit *ast.ObjectLiteral, routes *[]SemanticRoute, file string) {
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

	if right, ok := assign.Right.(*ast.StringLiteral); ok {
		val := stringLiteralValue(right)

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

	if strings.Contains(bodyLower, "import()") || strings.Contains(bodyLower, "require.ensure") {
		findings = append(findings, JSFinding{
			SourceURL: jsURL,
			Type:      "lazy_route",
			Name:      "Dynamic Import (Lazy Route)",
			Value:     "possible lazy-loaded route or chunk",
			Severity:  "low",
		})
	}

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

func scanSecrets(jsBody string, sourceURL string) []JSFinding {
	var findings []JSFinding

	for _, sp := range SecretPatterns {
		matches := sp.Pattern.FindAllString(jsBody, 5)
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

func scanEntropy(jsBody string, sourceURL string) []JSFinding {
	var findings []JSFinding

	stringPattern := regexp.MustCompile(`['"]([A-Za-z0-9+/=_\-]{20,})['"]`)
	matches := stringPattern.FindAllStringSubmatch(jsBody, 100)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		value := match[1]

		if isCommonFalsePositive(value) {
			continue
		}

		entropy := shannonEntropy(value)

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

func isNoiseEndpoint(ep string) bool {
	if len(ep) < 3 || len(ep) > 200 {
		return true
	}

	noisePatterns := []string{
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".css", ".woff", ".woff2", ".ttf", ".eot",
		".map", "webpack", "node_modules", "__webpack",
		"polyfill", "sourcemap", "chunk-", "vendor",
		"text/html", "text/plain", "text/css", "text/javascript",
		"application/json", "application/xml", "application/javascript",
		"multipart/form-data", "application/x-www-form-urlencoded",
		"image/", "audio/", "video/", "charset=", "utf-8", "us-ascii",
	}
	lower := strings.ToLower(ep)
	for _, n := range noisePatterns {
		if strings.Contains(lower, n) {
			return true
		}
	}

	return false
}

func isCommonFalsePositive(s string) bool {
	lower := strings.ToLower(s)

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
