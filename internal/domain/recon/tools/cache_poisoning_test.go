package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCachePoisoningTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Header.Get("X-Forwarded-Host") == "bbpts-poison-test.com" {
			w.Header().Set("Location", "http://bbpts-poison-test.com/redirect")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	tool := &CachePoisoningTool{}
	if tool.Name() != "cache_poisoning" {
		t.Errorf("expected tool name cache_poisoning, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundPoison := false
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		if name == "Host Header Injection / Cache Poisoning" {
			foundPoison = true
		}
	}

	if !foundPoison {
		t.Error("expected to detect Host Header Injection / Cache Poisoning")
	}
}
