package recon

import (
	"log/slog"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

// SemanticAnalyzer performs deep AST parsing of JavaScript files to extract routes and logic.
type SemanticAnalyzer struct{}

func NewSemanticAnalyzer() *SemanticAnalyzer {
	return &SemanticAnalyzer{}
}

// SemanticRoute represents an identified application state or endpoint.
type SemanticRoute struct {
	Path       string
	Method     string
	IsGraphQL  bool
	IsAuthFlow bool
	Variable   string
	SourceFile string
	Line       int
	Signature  string
}

// AnalyzeAST takes raw JS code, builds an AST, and extracts semantic meaning.
func (sa *SemanticAnalyzer) AnalyzeAST(sourceCode string) []SemanticRoute {
	var routes []SemanticRoute

	// Parse the JS file into an AST
	program, err := parser.ParseFile(nil, "bundle.js", sourceCode, 0, parser.WithDisableSourceMaps)
	if err != nil {
		slog.Debug("AST parsing failed, likely minified or unsupported syntax", "error", err)
		return nil
	}

	// Walk the AST looking for specific call expressions (fetch, axios, router, mutations)
	sa.walkAST(program, func(node ast.Node) {
		switch n := node.(type) {
		case *ast.CallExpression:
			// Look for fetch() or axios()
			if ident, ok := n.Callee.(*ast.Identifier); ok {
				if ident.Name == "fetch" || ident.Name == "axios" {
					if len(n.ArgumentList) > 0 {
						if str, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
							valStr := str.Value.String()
							route := SemanticRoute{Path: valStr, Method: "UNKNOWN"}

							if strings.Contains(valStr, "graphql") {
								route.IsGraphQL = true
							}
							if strings.Contains(strings.ToLower(valStr), "auth") || strings.Contains(strings.ToLower(valStr), "login") {
								route.IsAuthFlow = true
							}

							// If there's a second argument (fetch options), we could extract method, but we'll stick to basic mapping here
							routes = append(routes, route)
						}
					}
				}
			}
		case *ast.ObjectLiteral:
			// Look for React Router / Vue Router path definitions: { path: '/login', component: ... }
			hasPath := false
			pathVal := ""
			for _, prop := range n.Value {
				if propObj, ok := prop.(*ast.PropertyKeyed); ok {
					if propertyKeyName(propObj.Key) == "path" {
						if strVal, ok := propObj.Value.(*ast.StringLiteral); ok {
							hasPath = true
							pathVal = stringLiteralValue(strVal)
						}
					}
				}
			}
			if hasPath {
				routes = append(routes, SemanticRoute{
					Path:       pathVal,
					Method:     "GET (Router)",
					IsAuthFlow: strings.Contains(pathVal, "login") || strings.Contains(pathVal, "auth"),
				})
			}
		}
	})

	return routes
}

// walkAST recursively visits all nodes in the AST.
func (sa *SemanticAnalyzer) walkAST(node ast.Node, visitor func(ast.Node)) {
	walkJSAST(node, visitor)
}
