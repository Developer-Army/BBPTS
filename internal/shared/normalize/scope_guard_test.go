package normalize

import "testing"

func TestScopeGuardAllowsURLsWithinScope(t *testing.T) {
	guard := NewScopeGuard([]string{"example.com"})

	if !guard.IsAllowed("https://api.example.com/v1/users") {
		t.Fatal("expected URL within scope to be allowed")
	}
	if !guard.IsAllowed("admin.example.com:8443") {
		t.Fatal("expected host with port to be allowed")
	}
}

func TestScopeGuardBlocksOutOfScopeTargets(t *testing.T) {
	guard := NewScopeGuard([]string{"example.com"})
	filtered := guard.Filter([]string{
		"https://api.example.com/v1/users",
		"https://evil-example.com/login",
		"internal.other.org",
	})

	if len(filtered) != 1 || filtered[0] != "https://api.example.com/v1/users" {
		t.Fatalf("unexpected filtered targets: %#v", filtered)
	}
}
