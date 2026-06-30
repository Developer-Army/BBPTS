package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOAuthTesterTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if q.Get("redirect_uri") == "https://example.com" {
			w.Header().Set("Location", "https://example.com/callback")
			w.WriteHeader(http.StatusFound)
			return
		}

		if q.Get("state") == "" || q.Get("response_type") == "token" || (q.Get("client_id") != "" && q.Get("code_challenge") == "") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("mock authorization screen"))
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	tool := &OAuthTesterTool{}
	if tool.Name() != "oauth" {
		t.Errorf("expected tool name oauth, got %s", tool.Name())
	}

	targetURL := server.URL + "/oauth/authorize?client_id=client123&response_type=code&redirect_uri=https://myhost.com/cb&state=secretstate&code_challenge=challenge&code_challenge_method=S256"

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{targetURL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundCSRF, foundOpenRedirect, foundImplicit, foundPKCE bool
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		switch name {
		case "OAuth 2.0 Missing State Parameter (CSRF)":
			foundCSRF = true
		case "OAuth 2.0 Open redirect_uri (Account Takeover)":
			foundOpenRedirect = true
		case "OAuth 2.0 Implicit Flow Enabled":
			foundImplicit = true
		case "OAuth 2.0 PKCE Bypass":
			foundPKCE = true
		}
	}

	if !foundCSRF {
		t.Error("expected to detect OAuth 2.0 Missing State Parameter (CSRF)")
	}
	if !foundOpenRedirect {
		t.Error("expected to detect OAuth 2.0 Open redirect_uri (Account Takeover)")
	}
	if !foundImplicit {
		t.Error("expected to detect OAuth 2.0 Implicit Flow Enabled")
	}
	if !foundPKCE {
		t.Error("expected to detect OAuth 2.0 PKCE Bypass")
	}
}
