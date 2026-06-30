package recon

import (
	"log/slog"
	"strings"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

type SemanticAnalyzer struct{}

func NewSemanticAnalyzer() *SemanticAnalyzer {
	return &SemanticAnalyzer{}
}

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

func (sa *SemanticAnalyzer) AnalyzeAST(sourceCode string) []SemanticRoute {
	program, err := parser.ParseFile(nil, "bundle.js", sourceCode, 0, parser.WithDisableSourceMaps)
	var routes []SemanticRoute
	if err == nil {
		routes = sa.extract(program)
	}

	if err != nil || len(routes) == 0 {
		trimmed := strings.TrimSpace(sourceCode)
		trimmed = strings.TrimSuffix(trimmed, ";")
		if program2, err2 := parser.ParseFile(nil, "bundle.js", "("+trimmed+")", 0, parser.WithDisableSourceMaps); err2 == nil {
			routes2 := sa.extract(program2)
			if len(routes2) > 0 {
				return routes2
			}
		}
	}

	if err != nil {
		slog.Debug("AST parsing failed, likely minified or unsupported syntax", "error", err)
		return nil
	}

	if routes == nil {
		return []SemanticRoute{}
	}
	return routes
}

func (sa *SemanticAnalyzer) extract(program *ast.Program) []SemanticRoute {
	routes := []SemanticRoute{}
	sa.walkAST(program, func(node ast.Node) {
		switch n := node.(type) {
		case *ast.CallExpression:
			isCall := false
			method := "UNKNOWN"
			if ident, ok := n.Callee.(*ast.Identifier); ok {
				if ident.Name == "fetch" || ident.Name == "axios" {
					isCall = true
				}
			} else if dot, ok := n.Callee.(*ast.DotExpression); ok {
				if leftIdent, ok := dot.Left.(*ast.Identifier); ok && leftIdent.Name == "axios" {
					isCall = true
					method = strings.ToUpper(dot.Identifier.Name.String())
				}
			}

			if isCall {
				if len(n.ArgumentList) > 0 {
					if str, ok := n.ArgumentList[0].(*ast.StringLiteral); ok {
						valStr := str.Value.String()
						route := SemanticRoute{Path: valStr, Method: method}

						if strings.Contains(valStr, "graphql") {
							route.IsGraphQL = true
						}
						if strings.Contains(strings.ToLower(valStr), "auth") || strings.Contains(strings.ToLower(valStr), "login") {
							route.IsAuthFlow = true
						}

						routes = append(routes, route)
					}
				}
			}
		case *ast.ObjectLiteral:
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

func (sa *SemanticAnalyzer) walkAST(node ast.Node, visitor func(ast.Node)) {
	walkJSAST(node, visitor)
}
