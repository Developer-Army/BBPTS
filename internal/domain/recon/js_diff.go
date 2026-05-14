package recon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

// --- Regex fallback patterns for minified/obfuscated JS ---
var fallbackEndpointPatterns = []*regexp.Regexp{
	regexp.MustCompile(`['"](/api/[a-zA-Z0-9_/\-{}:.]+)['"]`),
	regexp.MustCompile(`['"](/v[0-9]+/[a-zA-Z0-9_/\-{}:.]+)['"]`),
	regexp.MustCompile(`['"](/graphql[a-zA-Z0-9_/\-{}:.]*?)['"]`),
	regexp.MustCompile(`['"]([a-zA-Z0-9_\-]+/[a-zA-Z0-9_/\-{}:.]+)['"]`),
	regexp.MustCompile(`['"]https?://[a-zA-Z0-9.\-]+(?::[0-9]+)?/[a-zA-Z0-9_/\-{}:.?&=]+['"]`),
	regexp.MustCompile(`(?:fetch|axios|XMLHttpRequest|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*['"]([^'"]+)['"]`),
	regexp.MustCompile("`" + `(https?://[^` + "`" + `]+)` + "`"),
}

func regexExtractRoutes(js string) []SemanticRoute {
	var routes []SemanticRoute
	for _, pat := range fallbackEndpointPatterns {
		matches := pat.FindAllStringSubmatch(js, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			path := strings.Trim(m[1], `'"`)
			if len(path) < 2 || strings.Contains(path, ".js") {
				continue
			}
			routes = append(routes, SemanticRoute{
				Path:       path,
				Method:     "UNKNOWN",
				SourceFile: "regex_fallback",
			})
		}
	}
	return routes
}

// --- Core diff structures ---

// JSBundleDiff compares two JavaScript bundles and reports semantic changes.
type JSBundleDiff struct {
	OldHash   string
	NewHash   string
	Added     []SemanticRoute
	Removed   []SemanticRoute
	Modified  []RouteModification
	Unchanged []SemanticRoute
}

// RouteModification describes a changed route between versions.
type RouteModification struct {
	Route      SemanticRoute
	ChangeType string // "method_changed", "path_normalized", "variable_renamed"
	OldValue   string
	NewValue   string
}

// --- Public API ---

// DiffBundles performs a semantic diff between two JS source codes.
func DiffBundles(oldJS, newJS string) *JSBundleDiff {
	oldRoutes := extractAllRoutes(oldJS)
	newRoutes := extractAllRoutes(newJS)

	oldMap := make(map[string]SemanticRoute)
	newMap := make(map[string]SemanticRoute)

	for _, r := range oldRoutes {
		r.Signature = computeRouteSignature(r)
		oldMap[r.Signature] = r
	}
	for _, r := range newRoutes {
		r.Signature = computeRouteSignature(r)
		newMap[r.Signature] = r
	}

	diff := &JSBundleDiff{
		OldHash: hashBundle(oldJS),
		NewHash: hashBundle(newJS),
	}

	for sig, newRoute := range newMap {
		if oldRoute, exists := oldMap[sig]; exists {
			if oldRoute.Method != newRoute.Method {
				diff.Modified = append(diff.Modified, RouteModification{
					Route:      newRoute,
					ChangeType: "method_changed",
					OldValue:   oldRoute.Method,
					NewValue:   newRoute.Method,
				})
			} else {
				diff.Unchanged = append(diff.Unchanged, newRoute)
			}
		} else {
			diff.Added = append(diff.Added, newRoute)
		}
	}

	for sig, oldRoute := range oldMap {
		if _, exists := newMap[sig]; !exists {
			diff.Removed = append(diff.Removed, oldRoute)
		}
	}

	return diff
}

// extractAllRoutes returns deduped routes from JS using AST first, regex fallback.
func extractAllRoutes(js string) []SemanticRoute {
	// Try AST parsing first
	program, err := parser.ParseFile(nil, "bundle.js", js, 0, parser.WithDisableSourceMaps)
	if err != nil {
		// Fallback to regex (minified/unsupported syntax)
		slog.Debug("AST parse failed in JS diff, using regex fallback", "error", err)
		return regexExtractRoutes(js)
	}

	var routes []SemanticRoute
	walkJSAST(program, func(n ast.Node) {
		extractRoutesFromNode(n, &routes)
	})

	// Deduplicate by signature
	seen := make(map[string]struct{})
	uniq := make([]SemanticRoute, 0, len(routes))
	for _, r := range routes {
		sig := computeRouteSignature(r)
		if _, ok := seen[sig]; !ok {
			seen[sig] = struct{}{}
			uniq = append(uniq, r)
		}
	}
	return uniq
}

// extractRoutesFromNode walks AST nodes and appends discovered routes.
func extractRoutesFromNode(node ast.Node, routes *[]SemanticRoute) {
	switch n := node.(type) {
	case *ast.CallExpression:
		extractFetchCall(n, routes)
		extractRouterMethodCall(n, routes)
	case *ast.ObjectLiteral:
		extractPathObject(n, routes)
	case *ast.AssignExpression:
		extractConstAssign(n, routes)
	case *ast.NewExpression:
		extractRouterConfig(n, routes)
	}
}

// extractFetchCall handles: fetch('/api/users', {method: 'POST'})
func extractFetchCall(call *ast.CallExpression, routes *[]SemanticRoute) {
	if ident, ok := call.Callee.(*ast.Identifier); ok && ident.Name == "fetch" && len(call.ArgumentList) >= 1 {
		method := "GET"
		// Look for method option
		if len(call.ArgumentList) >= 2 {
			if opts, ok := call.ArgumentList[1].(*ast.ObjectLiteral); ok {
				for _, prop := range opts.Value {
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
				IsGraphQL:  strings.Contains(strings.ToLower(path), "graphql"),
				SourceFile: "bundle.js",
			})
		}
	}
}

// extractRouterMethodCall handles: router.get('/admin', handler)
func extractRouterMethodCall(call *ast.CallExpression, routes *[]SemanticRoute) {
	member, ok := call.Callee.(*ast.DotExpression)
	if !ok {
		return
	}
	method := strings.ToUpper(member.Identifier.Name.String())
	if method != "GET" && method != "POST" && method != "PUT" && method != "DELETE" && method != "PATCH" {
		return
	}
	if len(call.ArgumentList) >= 1 {
		if str, ok := call.ArgumentList[0].(*ast.StringLiteral); ok {
			*routes = append(*routes, SemanticRoute{
				Path:       stringLiteralValue(str),
				Method:     method,
				SourceFile: "bundle.js",
			})
		}
	}
}

// extractPathObject handles: { path: '/login', component: LoginPage }
func extractPathObject(obj *ast.ObjectLiteral, routes *[]SemanticRoute) {
	for _, prop := range obj.Value {
		if keyed, ok := prop.(*ast.PropertyKeyed); ok && propertyKeyName(keyed.Key) == "path" {
			if str, ok := keyed.Value.(*ast.StringLiteral); ok {
				*routes = append(*routes, SemanticRoute{
					Path:       stringLiteralValue(str),
					Method:     "GET",
					SourceFile: "bundle.js",
				})
			}
		}
	}
}

// extractConstAssign handles: const API_URL = '/api/v1/';
func extractConstAssign(assign *ast.AssignExpression, routes *[]SemanticRoute) {
	if str, ok := assign.Right.(*ast.StringLiteral); ok {
		val := stringLiteralValue(str)
		if strings.HasPrefix(val, "/") && (strings.Contains(val, "api") || strings.Contains(val, "/v") || strings.Contains(val, "graphql")) {
			var varName string
			if ident, ok := assign.Left.(*ast.Identifier); ok {
				varName = ident.Name.String()
			}
			*routes = append(*routes, SemanticRoute{
				Path:       val,
				Method:     "UNKNOWN",
				Variable:   varName,
				SourceFile: "bundle.js",
			})
		}
	}
}

// extractRouterConfig handles: new Router({ routes: [{ path: '/', component: Home }] })
func extractRouterConfig(expr *ast.NewExpression, routes *[]SemanticRoute) {
	if len(expr.ArgumentList) == 0 {
		return
	}
	if obj, ok := expr.ArgumentList[0].(*ast.ObjectLiteral); ok {
		for _, prop := range obj.Value {
			if keyed, ok := prop.(*ast.PropertyKeyed); ok && propertyKeyName(keyed.Key) == "routes" {
				if arr, ok := keyed.Value.(*ast.ArrayLiteral); ok {
					for _, item := range arr.Value {
						if itemObj, ok := item.(*ast.ObjectLiteral); ok {
							extractPathObject(itemObj, routes)
						}
					}
				}
			}
		}
	}
}

// --- Signature & hashing ---

func computeRouteSignature(r SemanticRoute) string {
	norm := r.Path
	if idx := strings.Index(norm, "?"); idx >= 0 {
		norm = norm[:idx]
	}
	norm = strings.TrimSuffix(norm, "/")
	if norm == "" {
		norm = "/"
	}
	data := fmt.Sprintf("%s|%s|%s|%s", norm, r.Method, r.Variable, r.SourceFile)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:8])
}

func hashBundle(js string) string {
	h := sha256.Sum256([]byte(js))
	return hex.EncodeToString(h[:16])
}

// --- Analysis helpers ---

// Summary returns a concise human-readable diff summary.
func (d *JSBundleDiff) Summary() string {
	total := len(d.Added) + len(d.Removed) + len(d.Modified)
	if total == 0 {
		return "No semantic changes detected in JavaScript bundles"
	}
	return fmt.Sprintf("JS diff: +%d routes, -%d routes, ~%d modified",
		len(d.Added), len(d.Removed), len(d.Modified))
}

// HighValueChanges filters added/removed routes to those likely high-impact.
func (d *JSBundleDiff) HighValueChanges() []SemanticRoute {
	var high []SemanticRoute
	for _, r := range d.Added {
		if isHighValueRoute(r) {
			high = append(high, r)
		}
	}
	for _, r := range d.Removed {
		if isHighValueRoute(r) {
			high = append(high, r)
		}
	}
	return high
}

func isHighValueRoute(r SemanticRoute) bool {
	path := strings.ToLower(r.Path)
	highValueKeywords := []string{
		"admin", "api", "graphql", "auth", "login", "logout",
		"payment", "checkout", "user", "account", "profile",
		"internal", "debug", "test", "staging", "dev",
		"upload", "download", "export", "import",
		"setting", "config", "secret", "key", "token",
	}
	for _, kw := range highValueKeywords {
		if strings.Contains(path, kw) {
			return true
		}
	}
	if r.IsGraphQL {
		return true
	}
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
		return true
	}
	return false
}
