package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProtoPollutionTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		bodyStr := string(bodyBytes)

		if strings.Contains(bodyStr, `"__proto__"`) && strings.Contains(bodyStr, `"bbpts_polluted"`) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","bbpts_polluted":"yes_proto"}`))
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	tool := &ProtoPollutionTool{}
	if tool.Name() != "proto_pollution" {
		t.Errorf("expected tool name proto_pollution, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundServerSide := false
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		if name == "Server-Side Prototype Pollution (JSON Body Injection)" {
			foundServerSide = true
		}
	}

	if !foundServerSide {
		t.Error("expected to detect Server-Side Prototype Pollution (JSON Body Injection)")
	}
}
