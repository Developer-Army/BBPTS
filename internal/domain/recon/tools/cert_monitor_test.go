package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCertMonitorTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[
			{"common_name":"api.example.com","name_value":"api.example.com"},
			{"common_name":"example.com","name_value":"admin.example.com\nportal.example.com"}
		]`))
	}))
	defer server.Close()

	oldURL := crtshAPIURL
	crtshAPIURL = server.URL
	defer func() { crtshAPIURL = oldURL }()

	tool := &CertMonitorTool{}
	if tool.Name() != "cert_monitor" {
		t.Errorf("expected tool name cert_monitor, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{"example.com"}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundAPI, foundAdmin, foundPortal bool
	for _, ev := range events {
		if ev.Target == "api.example.com" {
			foundAPI = true
		}
		if ev.Target == "admin.example.com" {
			foundAdmin = true
		}
		if ev.Target == "portal.example.com" {
			foundPortal = true
		}
	}

	if !foundAPI || !foundAdmin || !foundPortal {
		t.Errorf("expected to discover subdomains api, admin, portal, got %v", events)
	}
}
