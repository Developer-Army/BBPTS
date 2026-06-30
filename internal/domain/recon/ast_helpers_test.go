package recon

import (
	"testing"

	"github.com/dop251/goja/ast"
	"github.com/dop251/goja/parser"
)

func TestStringLiteralValue(t *testing.T) {
	tests := []struct {
		name     string
		lit      *ast.StringLiteral
		expected string
	}{
		{"simple string", &ast.StringLiteral{Value: "hello"}, "hello"},
		{"empty string", &ast.StringLiteral{Value: ""}, ""},
		{"nil literal", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stringLiteralValue(tt.lit)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestPropertyKeyName(t *testing.T) {
	tests := []struct {
		name     string
		key      ast.Expression
		expected string
	}{
		{"identifier", &ast.Identifier{Name: "myKey"}, "myKey"},
		{"string literal", &ast.StringLiteral{Value: "myKey"}, "myKey"},
		{"empty string literal", &ast.StringLiteral{Value: ""}, ""},
		{"nil", nil, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := propertyKeyName(tt.key)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

func TestWalkJSAST(t *testing.T) {

	code := `const x = 5;`
	program, err := parser.ParseFile(nil, "test.js", code, 0)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	visited := false
	walkJSAST(program, func(node ast.Node) {
		visited = true
	})

	if !visited {
		t.Error("walkJSAST should visit at least one node")
	}
}

func TestWalkJSAST_Nil(t *testing.T) {

	walkJSAST(nil, func(node ast.Node) {
		t.Error("should not call visitor on nil")
	})
}

func TestWalkJSAST_VisitorCalled(t *testing.T) {
	code := `const x = 5; function foo() { return x; }`
	program, err := parser.ParseFile(nil, "test.js", code, 0)
	if err != nil {
		t.Fatalf("ParseFile failed: %v", err)
	}

	visitCount := 0
	walkJSAST(program, func(node ast.Node) {
		visitCount++
	})

	if visitCount == 0 {
		t.Error("visitor should be called at least once")
	}

	if visitCount < 5 {
		t.Errorf("expected more visits, got %d", visitCount)
	}
}
