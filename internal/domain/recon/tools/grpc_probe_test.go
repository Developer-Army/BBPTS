package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestGRPCProbeTool(t *testing.T) {

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("grpc-status", "3")
		w.WriteHeader(http.StatusOK)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	u, _ := url.Parse(server.URL)

	tool := &GRPCProbeTool{}
	if tool.Name() != "grpc_probe" {
		t.Errorf("expected tool name grpc_probe, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{u.Hostname() + ":" + u.Port()}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// We scanned using localhost, which should resolve and hit our StartTLS server
	var foundService, foundReflection bool
	for _, ev := range events {
		if ev.Type == "discovery" && ev.Properties["type"] == "grpc_service" {
			foundService = true
		}
		if ev.Type == "vulnerability" && ev.Properties["vuln_name"] == "gRPC Server Reflection Enabled" {
			foundReflection = true
		}
	}

	if !foundService {
		t.Error("expected to discover gRPC service event")
	}
	if !foundReflection {
		t.Error("expected to discover gRPC Server Reflection Enabled vulnerability")
	}
}
