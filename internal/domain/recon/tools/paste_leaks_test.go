package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasteLeaksTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "search") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"id":"dump1"}]`))
			return
		}
		if strings.Contains(r.URL.Path, "dump") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`// config file for example.com
api_key = "secret_key_1234567890"
password: "admin_secret_password"
`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	oldBase := psbdmpBaseURL
	psbdmpBaseURL = server.URL
	defer func() { psbdmpBaseURL = oldBase }()

	tool := &PasteLeaksTool{}
	if tool.Name() != "paste_leaks" {
		t.Errorf("expected tool name paste_leaks, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{"example.com"}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Properties["vuln_name"] != "Sensitive Data Exposure in Public Paste" {
		t.Errorf("expected vuln name, got %s", ev.Properties["vuln_name"])
	}
	if !strings.Contains(ev.Properties["evidence"], "api_key") {
		t.Errorf("expected api_key in evidence, got %s", ev.Properties["evidence"])
	}
}
