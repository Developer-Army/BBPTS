package recon

import (
	"testing"
	"time"
)

func TestNewIntrospector(t *testing.T) {
	gi := NewIntrospector(10 * time.Second)
	if gi == nil {
		t.Fatal("NewIntrospector returned nil")
	}
	if gi.client == nil {
		t.Error("client not initialized")
	}
	if gi.timeout != 10*time.Second {
		t.Errorf("expected timeout 10s, got %v", gi.timeout)
	}
	if gi.headers == nil {
		t.Error("headers map not initialized")
	}
}

func TestIntrospector_SetHeader(t *testing.T) {
	gi := NewIntrospector(10 * time.Second)
	gi.SetHeader("Authorization", "Bearer token")

	if gi.headers["Authorization"] != "Bearer token" {
		t.Errorf("expected header 'Authorization: Bearer token', got '%s'", gi.headers["Authorization"])
	}
}

func TestIntrospector_SetHeader_Override(t *testing.T) {
	gi := NewIntrospector(10 * time.Second)
	gi.SetHeader("X-Custom", "value1")
	gi.SetHeader("X-Custom", "value2")

	if gi.headers["X-Custom"] != "value2" {
		t.Errorf("expected header to be overridden to 'value2', got '%s'", gi.headers["X-Custom"])
	}
}

func TestIntrospectionQuery(t *testing.T) {
	if IntrospectionQuery == "" {
		t.Error("IntrospectionQuery should not be empty")
	}

	// Verify it contains key GraphQL introspection fields
	requiredFields := []string{"__schema", "queryType", "mutationType", "types", "fields"}
	for _, field := range requiredFields {
		if !contains(IntrospectionQuery, field) {
			t.Errorf("IntrospectionQuery should contain field '%s'", field)
		}
	}
}

func TestSchemaAnalysis_ToMarkdown(t *testing.T) {
	schema := &Schema{
		QueryType:        "Query",
		MutationType:     "Mutation",
		SubscriptionType: "Subscription",
	}

	analysis := &SchemaAnalysis{
		Schema:           schema,
		QueryFields:      []string{"user", "post"},
		MutationFields:   []string{"createUser", "deleteUser"},
		SensitiveFields:  []string{"Query.password", "Mutation.token"},
		DeprecatedFields: []string{"Query.oldField"},
		EnumTypes:        []string{"Role", "Status"},
		InputTypes:       []string{"UserInput", "PostInput"},
	}

	markdown := analysis.ToMarkdown()

	if markdown == "" {
		t.Error("ToMarkdown should not return empty string")
	}

	// Verify markdown contains expected sections
	expectedSections := []string{"GraphQL Schema Analysis", "Query Type", "Mutation Type", "Summary", "Query Fields", "Mutation Fields", "Sensitive Fields"}
	for _, section := range expectedSections {
		if !contains(markdown, section) {
			t.Errorf("Markdown should contain section '%s'", section)
		}
	}
}

func TestSchemaAnalysis_ToJSON(t *testing.T) {
	schema := &Schema{
		QueryType: "Query",
	}

	analysis := &SchemaAnalysis{
		Schema:      schema,
		QueryFields: []string{"user"},
	}

	json, err := analysis.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	if json == "" {
		t.Error("ToJSON should not return empty string")
	}

	// Verify it's valid JSON by checking for expected fields
	if !contains(json, "QueryFields") {
		t.Error("JSON should contain QueryFields")
	}
}

func TestIntrospector_GenerateTestQueries(t *testing.T) {
	analysis := &SchemaAnalysis{
		QueryFields:    []string{"user", "post"},
		MutationFields: []string{"createUser", "deleteUser"},
	}

	gi := NewIntrospector(10 * time.Second)
	queries := gi.GenerateTestQueries(analysis)

	if len(queries) == 0 {
		t.Error("GenerateTestQueries should return at least one query")
	}

	// Should have 2 query tests + 2 mutation tests + 1 introspection = 5
	if len(queries) != 5 {
		t.Errorf("expected 5 queries, got %d", len(queries))
	}

	// Verify introspection query is included
	foundIntrospection := false
	for _, q := range queries {
		if contains(q, "__schema") {
			foundIntrospection = true
			break
		}
	}
	if !foundIntrospection {
		t.Error("queries should include introspection query")
	}
}

func TestIntrospector_GenerateTestQueries_Empty(t *testing.T) {
	analysis := &SchemaAnalysis{
		QueryFields:    []string{},
		MutationFields: []string{},
	}

	gi := NewIntrospector(10 * time.Second)
	queries := gi.GenerateTestQueries(analysis)

	// Should still have introspection query
	if len(queries) != 1 {
		t.Errorf("expected 1 query (introspection only), got %d", len(queries))
	}
}

func TestIsSensitiveField(t *testing.T) {
	tests := []struct {
		name     string
		field    string
		expected bool
	}{
		{"password", "password", true},
		{"token", "token", true},
		{"secret", "secret", true},
		{"apiKey", "apiKey", true},
		{"creditCard", "creditCard", true},
		{"normal field", "name", false},
		{"id", "id", false},
		{"title", "title", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSensitiveField(tt.field)
			if result != tt.expected {
				t.Errorf("expected %v for field '%s', got %v", tt.expected, tt.field, result)
			}
		})
	}
}

func TestIsSensitiveField_CaseInsensitive(t *testing.T) {
	tests := []string{"Password", "PASSWORD", "PaSsWoRd"}
	for _, field := range tests {
		if !isSensitiveField(field) {
			t.Errorf("isSensitiveField should be case insensitive for '%s'", field)
		}
	}
}

func TestIsSensitiveField_ContainsKeyword(t *testing.T) {
	tests := []struct {
		field    string
		expected bool
	}{
		{"userPassword", true},
		{"authToken", true},
		{"secretKey", true},
		{"apiKey", true},
		{"passwordReset", true},
		{"username", true},
		{"user", true},
		{"fieldname", false},
	}

	for _, tt := range tests {
		if isSensitiveField(tt.field) != tt.expected {
			t.Errorf("expected %v for field '%s'", tt.expected, tt.field)
		}
	}
}

func TestIntrospector_Analyze(t *testing.T) {
	schema := &Schema{
		QueryType:    "Query",
		MutationType: "Mutation",
		Types: []Type{
			{
				Name: "Query",
				Kind: "OBJECT",
				Fields: []Field{
					{Name: "user", Type: TypeRef{Name: "User"}},
					{Name: "password", Type: TypeRef{Name: "String"}, IsDeprecated: true},
				},
			},
			{
				Name: "Mutation",
				Kind: "OBJECT",
				Fields: []Field{
					{Name: "createUser", Type: TypeRef{Name: "User"}},
					{Name: "deleteToken", Type: TypeRef{Name: "Boolean"}},
				},
			},
			{
				Name: "__Schema",
				Kind: "OBJECT",
			},
			{
				Name: "Role",
				Kind: "ENUM",
			},
			{
				Name: "UserInput",
				Kind: "INPUT_OBJECT",
			},
		},
	}

	gi := NewIntrospector(10 * time.Second)
	analysis := gi.Analyze(schema)

	if analysis == nil {
		t.Fatal("Analyze should not return nil")
	}

	if analysis.Schema != schema {
		t.Error("Analysis should contain the original schema")
	}

	// Should identify query fields
	if len(analysis.QueryFields) != 2 {
		t.Errorf("expected 2 query fields, got %d", len(analysis.QueryFields))
	}

	// Should identify mutation fields
	if len(analysis.MutationFields) != 2 {
		t.Errorf("expected 2 mutation fields, got %d", len(analysis.MutationFields))
	}

	// Should identify sensitive fields
	if len(analysis.SensitiveFields) == 0 {
		t.Error("should identify sensitive fields like 'password' and 'deleteToken'")
	}

	// Should identify deprecated fields
	if len(analysis.DeprecatedFields) == 0 {
		t.Error("should identify deprecated fields")
	}

	// Should identify enum types
	if len(analysis.EnumTypes) != 1 {
		t.Errorf("expected 1 enum type, got %d", len(analysis.EnumTypes))
	}

	// Should identify input types
	if len(analysis.InputTypes) != 1 {
		t.Errorf("expected 1 input type, got %d", len(analysis.InputTypes))
	}
}

func TestIntrospector_Analyze_EmptySchema(t *testing.T) {
	schema := &Schema{
		QueryType: "Query",
		Types:     []Type{},
	}

	gi := NewIntrospector(10 * time.Second)
	analysis := gi.Analyze(schema)

	if analysis == nil {
		t.Fatal("Analyze should not return nil")
	}

	if len(analysis.QueryFields) != 0 {
		t.Errorf("expected 0 query fields, got %d", len(analysis.QueryFields))
	}
}

func TestIntrospector_Analyze_SkipsIntrospectionTypes(t *testing.T) {
	schema := &Schema{
		QueryType: "Query",
		Types: []Type{
			{
				Name: "__Type",
				Kind: "OBJECT",
			},
			{
				Name: "__Schema",
				Kind: "OBJECT",
			},
			{
				Name: "__Directive",
				Kind: "OBJECT",
			},
		},
	}

	gi := NewIntrospector(10 * time.Second)
	analysis := gi.Analyze(schema)

	// Introspection types should be skipped
	if len(analysis.EnumTypes) != 0 {
		t.Error("introspection types should not be counted as enum types")
	}
}

func TestSchemaAnalysis_ToMarkdown_Empty(t *testing.T) {
	schema := &Schema{
		QueryType: "Query",
	}

	analysis := &SchemaAnalysis{
		Schema: schema,
	}

	markdown := analysis.ToMarkdown()

	if markdown == "" {
		t.Error("ToMarkdown should not return empty string")
	}

	// Should still have basic structure
	if !contains(markdown, "GraphQL Schema Analysis") {
		t.Error("Markdown should have title")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && findSubstring(s, substr))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
