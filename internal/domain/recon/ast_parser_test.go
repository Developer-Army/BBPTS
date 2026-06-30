package recon

import (
	"testing"

	"github.com/dop251/goja/ast"
)

func TestNewSemanticAnalyzer(t *testing.T) {
	sa := NewSemanticAnalyzer()

	if sa == nil {
		t.Fatal("NewSemanticAnalyzer should not return nil")
	}
}

func TestSemanticAnalyzer_AnalyzeAST(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `const api = '/api/users'; fetch('/admin');`

	routes := sa.AnalyzeAST(js)

	if routes == nil {
		t.Fatal("AnalyzeAST should not return nil")
	}

	if len(routes) == 0 {
		t.Error("should extract at least one route")
	}

	for _, route := range routes {
		if route.Path == "" {
			t.Error("route path should not be empty")
		}
		if route.Method == "" {
			t.Error("route method should not be empty")
		}
	}
}

func TestSemanticAnalyzer_AnalyzeAST_Fetch(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `fetch('/api/users');`

	routes := sa.AnalyzeAST(js)

	if len(routes) == 0 {
		t.Error("should extract fetch call")
	}

	found := false
	for _, route := range routes {
		if contains(route.Path, "/api/users") {
			found = true
			break
		}
	}

	if !found {
		t.Error("should detect fetch call to /api/users")
	}
}

func TestSemanticAnalyzer_AnalyzeAST_Axios(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `axios.get('/api/posts');`

	routes := sa.AnalyzeAST(js)

	if len(routes) == 0 {
		t.Error("should extract axios call")
	}

	found := false
	for _, route := range routes {
		if contains(route.Path, "/api/posts") {
			found = true
			break
		}
	}

	if !found {
		t.Error("should detect axios call to /api/posts")
	}
}

func TestSemanticAnalyzer_AnalyzeAST_GraphQL(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `fetch('/graphql');`

	routes := sa.AnalyzeAST(js)

	if len(routes) == 0 {
		t.Error("should extract GraphQL endpoint")
	}

	foundGraphQL := false
	for _, route := range routes {
		if route.IsGraphQL {
			foundGraphQL = true
			break
		}
	}

	if !foundGraphQL {
		t.Error("should detect GraphQL endpoint")
	}
}

func TestSemanticAnalyzer_AnalyzeAST_AuthFlow(t *testing.T) {
	sa := NewSemanticAnalyzer()

	tests := []struct {
		name string
		js   string
	}{
		{"login path", `fetch('/login');`},
		{"auth path", `fetch('/auth');`},
		{"login in object", `{ path: '/login' };`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := sa.AnalyzeAST(tt.js)

			foundAuth := false
			for _, route := range routes {
				if route.IsAuthFlow {
					foundAuth = true
					break
				}
			}

			if !foundAuth {
				t.Error("should detect auth flow")
			}
		})
	}
}

func TestSemanticAnalyzer_AnalyzeAST_ObjectLiteral(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `{ path: '/admin', component: Admin };`

	routes := sa.AnalyzeAST(js)

	if len(routes) == 0 {
		t.Error("should extract object literal path")
	}

	found := false
	for _, route := range routes {
		if contains(route.Path, "/admin") {
			found = true
			break
		}
	}

	if !found {
		t.Error("should extract path from object literal")
	}
}

func TestSemanticAnalyzer_AnalyzeAST_Empty(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `const x = 5;`

	routes := sa.AnalyzeAST(js)

	if routes == nil {
		t.Error("should return empty slice, not nil")
	}

	if len(routes) != 0 {
		t.Error("should not extract routes from empty JS")
	}
}

func TestSemanticAnalyzer_AnalyzeAST_Invalid(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `this is not valid javascript {{{`

	routes := sa.AnalyzeAST(js)

	if routes != nil {
		t.Error("should return nil for invalid JS")
	}
}

func TestSemanticAnalyzer_WalkAST(t *testing.T) {
	sa := NewSemanticAnalyzer()

	visited := false
	sa.walkAST(nil, func(node ast.Node) {
		visited = true
	})

	if visited {
		t.Error("should not visit nil node")
	}
}

func TestSemanticRoute_Structure(t *testing.T) {
	route := SemanticRoute{
		Path:       "/api/users",
		Method:     "GET",
		SourceFile: "bundle.js",
	}

	if route.Path != "/api/users" {
		t.Error("path should be set")
	}

	if route.Method != "GET" {
		t.Error("method should be set")
	}

	if route.SourceFile != "bundle.js" {
		t.Error("source file should be set")
	}
}

func TestSemanticAnalyzer_AnalyzeAST_MultipleRoutes(t *testing.T) {
	sa := NewSemanticAnalyzer()

	js := `
		fetch('/api/users');
		fetch('/api/posts');
		fetch('/admin');
		const config = { path: '/login' };
	`

	routes := sa.AnalyzeAST(js)

	if len(routes) < 3 {
		t.Errorf("should extract multiple routes, got %d", len(routes))
	}

	seen := make(map[string]bool)
	for _, route := range routes {
		if seen[route.Path] {
			t.Errorf("should not have duplicate routes: %s", route.Path)
		}
		seen[route.Path] = true
	}
}
