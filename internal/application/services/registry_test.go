package services

import "testing"

func TestGetToolByNameReturnsDalfox(t *testing.T) {
	tool, ok := GetToolByName("dalfox")
	if !ok {
		t.Fatal("expected dalfox to be registered in the tool registry")
	}
	if tool == nil {
		t.Fatal("expected non-nil Dalfox tool")
	}
	if tool.Name() != "dalfox" {
		t.Fatalf("expected tool name %q, got %q", "dalfox", tool.Name())
	}
}

func TestGetToolByNameReturnsShodan(t *testing.T) {
	tool, ok := GetToolByName("shodan")
	if !ok {
		t.Fatal("expected shodan to be registered in the tool registry")
	}
	if tool == nil {
		t.Fatal("expected non-nil Shodan tool")
	}
	if tool.Name() != "shodan" {
		t.Fatalf("expected tool name %q, got %q", "shodan", tool.Name())
	}
}

func TestGetToolByNameReturnsFindomain(t *testing.T) {
	tool, ok := GetToolByName("findomain")
	if !ok {
		t.Fatal("expected findomain to be registered in the tool registry")
	}
	if tool == nil {
		t.Fatal("expected non-nil Findomain tool")
	}
	if tool.Name() != "findomain" {
		t.Fatalf("expected tool name %q, got %q", "findomain", tool.Name())
	}
}

func TestGetToolByAliasWaybackurls(t *testing.T) {
	tool, ok := GetToolByName("waybackurls")
	if !ok {
		t.Fatal("expected waybackurls alias to map to a registered tool")
	}
	if tool == nil {
		t.Fatal("expected non-nil tool for waybackurls alias")
	}
	if tool.Name() != "gau" {
		t.Fatalf("expected waybackurls alias to map to gau, got %q", tool.Name())
	}
}

func TestGetToolByNameReturnsGowitness(t *testing.T) {
	tool, ok := GetToolByName("gowitness")
	if !ok {
		t.Fatal("expected gowitness to be registered in the tool registry")
	}
	if tool == nil {
		t.Fatal("expected non-nil Gowitness tool")
	}
	if tool.Name() != "gowitness" {
		t.Fatalf("expected tool name %q, got %q", "gowitness", tool.Name())
	}
}

func TestGetToolByNameReturnsGithub(t *testing.T) {
	tool, ok := GetToolByName("github")
	if !ok {
		t.Fatal("expected github to be registered in the tool registry")
	}
	if tool == nil {
		t.Fatal("expected non-nil Github tool")
	}
	if tool.Name() != "github" {
		t.Fatalf("expected tool name %q, got %q", "github", tool.Name())
	}
}

func TestGetToolByNameReturnsTLSX(t *testing.T) {
	tool, ok := GetToolByName("tlsx")
	if !ok {
		t.Fatal("expected tlsx to be registered in the tool registry")
	}
	if tool == nil {
		t.Fatal("expected non-nil TLSX tool")
	}
	if tool.Name() != "tlsx" {
		t.Fatalf("expected tool name %q, got %q", "tlsx", tool.Name())
	}
}

