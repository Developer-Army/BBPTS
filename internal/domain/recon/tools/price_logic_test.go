package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPriceLogicTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "cart") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"success","item_added":true}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &PriceLogicTool{}
	if tool.Name() != "price_logic" {
		t.Errorf("expected tool name price_logic, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) == 0 {
		t.Error("expected to discover price logic parameter tampering vulnerability")
	}

	ev := events[0]
	if ev.Properties["vuln_name"] != "Parameter Tampering: Price Logic Bypass" {
		t.Errorf("expected vuln name, got %s", ev.Properties["vuln_name"])
	}
}
