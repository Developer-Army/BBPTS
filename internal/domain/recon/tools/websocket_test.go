package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebSocketTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock response to simulate a successful WebSocket handshake upgrade on Origin: http://evil.com
		if r.Header.Get("Upgrade") == "websocket" && r.Header.Get("Origin") == "http://evil.com" {
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.WriteHeader(http.StatusSwitchingProtocols)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	tool := &WebSocketTool{}
	if tool.Name() != "websocket" {
		t.Errorf("expected tool name websocket, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	foundCSWSH := false
	for _, ev := range events {
		name := ev.Properties["vuln_name"]
		if name == "Cross-Site WebSocket Hijacking (CSWSH)" {
			foundCSWSH = true
		}
	}

	if !foundCSWSH {
		t.Error("expected to detect Cross-Site WebSocket Hijacking (CSWSH)")
	}
}
