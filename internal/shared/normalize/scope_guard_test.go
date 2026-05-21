package normalize

import "testing"

func TestScopeGuardAllowsURLsWithinScope(t *testing.T) {
	guard := NewScopeGuard([]string{"acme-corp.io"})

	if !guard.IsAllowed("https://api.acme-corp.io/v1/users") {
		t.Fatal("expected URL within scope to be allowed")
	}
	if !guard.IsAllowed("admin.acme-corp.io:8443") {
		t.Fatal("expected host with port to be allowed")
	}
}

func TestScopeGuardBlocksOutOfScopeTargets(t *testing.T) {
	guard := NewScopeGuard([]string{"acme-corp.io"})
	filtered := guard.Filter([]string{
		"https://api.acme-corp.io/v1/users",
		"https://evil-acme-corp.io/login",
		"internal.other.org",
	})

	if len(filtered) != 1 || filtered[0] != "https://api.acme-corp.io/v1/users" {
		t.Fatalf("unexpected filtered targets: %#v", filtered)
	}
}
