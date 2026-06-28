package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"strings"
	"testing"
)

func TestClassifyID(t *testing.T) {
	tests := []struct {
		value    string
		expected string
	}{
		{"12345", "numeric"},
		{"0", ""},
		{"", ""},
		{"550e8400-e29b-41d4-a716-446655440000", "uuid"},
		{"aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=", "base64"},
		{"abc123def456abc123", "hex"},
		{"hello-world", ""},
	}

	for _, tc := range tests {
		got := classifyID(tc.value)
		if got != tc.expected {
			t.Errorf("classifyID(%q) = %q; want %q", tc.value, got, tc.expected)
		}
	}
}

func TestIsIDLikeParamName(t *testing.T) {
	positives := []string{"id", "user_id", "userid", "order_id", "uuid", "token", "ref"}
	for _, name := range positives {
		if !isIDLikeParamName(name) {
			t.Errorf("isIDLikeParamName(%q) = false; want true", name)
		}
	}

	negatives := []string{"name", "email", "sort", "page", "limit", "format"}
	for _, name := range negatives {
		if isIDLikeParamName(name) {
			t.Errorf("isIDLikeParamName(%q) = true; want false", name)
		}
	}
}

func TestInferObjectType(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/api/users/123", "user"},
		{"/api/orders/456", "order"},
		{"/api/documents/789", "document"},
		{"/api/payments/abc", "payment"},
		{"/api/unknown/xyz", "unknown"},
	}

	for _, tc := range tests {
		got := inferObjectType(tc.path)
		if got != tc.expected {
			t.Errorf("inferObjectType(%q) = %q; want %q", tc.path, got, tc.expected)
		}
	}
}

func TestIDORAssistExtractAndCluster(t *testing.T) {
	tool := &IDORAssistTool{}
	urls := []string{
		"https://example.com/api/users/123",
		"https://example.com/api/users/456",
		"https://example.com/api/users/789",
		"https://example.com/api/orders?order_id=100",
		"https://example.com/api/orders?order_id=200",
		"https://example.com/api/orders?order_id=300",
	}

	clusters := tool.extractAndCluster(urls)
	if len(clusters) == 0 {
		t.Fatal("expected at least one IDOR cluster")
	}

	// Should have at least 2 clusters (users path + orders query)
	if len(clusters) < 2 {
		t.Errorf("expected >= 2 clusters, got %d", len(clusters))
	}

	// Check cluster properties
	for _, c := range clusters {
		if c.ObjectType == "" {
			t.Errorf("cluster %s has empty object type", c.Pattern)
		}
		if c.Risk == "" {
			t.Errorf("cluster %s has empty risk", c.Pattern)
		}
		if len(c.SampleIDs) < 2 {
			t.Errorf("cluster %s has < 2 sample IDs: %v", c.Pattern, c.SampleIDs)
		}
	}
}

func TestIDORAssistRun(t *testing.T) {
	tool := &IDORAssistTool{}
	if tool.Name() != "idor_assist" {
		t.Errorf("expected name 'idor_assist', got %q", tool.Name())
	}

	urls := []string{
		"https://example.com/api/users/123",
		"https://example.com/api/users/456",
		"https://example.com/api/documents?doc_id=550e8400-e29b-41d4-a716-446655440000",
		"https://example.com/api/documents?doc_id=660e9500-f39c-51e5-b827-557766551111",
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, urls, 2)
	if err != nil {
		t.Fatalf("IDORAssistTool.Run failed: %v", err)
	}

	if len(events) == 0 {
		t.Fatal("expected IDOR checklist events")
	}

	// Verify checklist content
	for _, ev := range events {
		if ev.Type != "idor_checklist" {
			continue
		}
		if ev.Properties["checklist"] == "" {
			t.Error("checklist event has empty checklist content")
		}
		if ev.Properties["object_type"] == "" {
			t.Error("checklist event has empty object_type")
		}
		if ev.Properties["risk"] == "" {
			t.Error("checklist event has empty risk")
		}
	}
}

func TestIDORAssistNoTargets(t *testing.T) {
	tool := &IDORAssistTool{}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, nil, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for nil targets, got %d", len(events))
	}
}

func TestBuildChecklist(t *testing.T) {
	tool := &IDORAssistTool{}
	cluster := idorCluster{
		Pattern:    "https://example.com/api/users/{id}",
		ParamName:  "users",
		ParamType:  "numeric",
		ObjectType: "user",
		Risk:       "high",
		SampleIDs:  []string{"123", "456", "789"},
		SampleURLs: []string{"https://example.com/api/users/123"},
		InPath:     true,
	}

	checklist := tool.buildChecklist(cluster)
	if checklist == "" {
		t.Fatal("buildChecklist returned empty string")
	}
	if !strings.Contains(checklist, "IDOR Test") {
		t.Error("checklist should contain 'IDOR Test' header")
	}
	if !strings.Contains(checklist, "HIGH VALUE TARGET") {
		t.Error("checklist for user object should contain HIGH VALUE TARGET warning")
	}
	if !strings.Contains(checklist, "Sequential enumeration") {
		t.Error("numeric ID checklist should mention sequential enumeration")
	}
}
