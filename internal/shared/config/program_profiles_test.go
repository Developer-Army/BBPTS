package config

import (
	"testing"
)

func TestFilterTargets(t *testing.T) {
	hosts := []string{"api.example.com", "bad.internal", "good.example.com"}
	p := ProgramProfile{
		ExcludeHosts:  []string{"bad.internal"},
		ExcludeSuffix: []string{".corp.example.com"},
	}
	hosts = append(hosts, "x.corp.example.com")
	got := FilterTargets(hosts, p)
	if len(got) != 2 {
		t.Fatalf("expected 2 hosts, got %d: %v", len(got), got)
	}
}

func TestFilterTargets_NoRules(t *testing.T) {
	hosts := []string{"a.com", "b.com"}
	got := FilterTargets(hosts, ProgramProfile{})
	if len(got) != 2 {
		t.Fatal("expected passthrough")
	}
}
