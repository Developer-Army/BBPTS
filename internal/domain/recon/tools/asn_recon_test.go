package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestASNReconTool(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "asn-by-ip") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"asns":["15169"]}}`))
			return
		}
		if strings.Contains(r.URL.Path, "announced-prefixes") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"data":{"prefixes":[{"prefix":"8.8.8.0/24"},{"prefix":"8.8.4.0/24"}]}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	oldBase := ripeBaseURL
	ripeBaseURL = server.URL
	defer func() { ripeBaseURL = oldBase }()

	tool := &ASNReconTool{}
	if tool.Name() != "asn_recon" {
		t.Errorf("expected tool name asn_recon, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{"127.0.0.1"}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundPrefix1, foundPrefix2 bool
	for _, ev := range events {
		if ev.Target == "8.8.8.0/24" {
			foundPrefix1 = true
		}
		if ev.Target == "8.8.4.0/24" {
			foundPrefix2 = true
		}
	}

	if !foundPrefix1 || !foundPrefix2 {
		t.Errorf("expected to find prefixes 8.8.8.0/24 and 8.8.4.0/24, got %v", events)
	}
}
