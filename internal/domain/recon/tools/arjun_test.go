package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestArjunTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
	}))
	defer server.Close()

	tool := &ArjunTool{}
	if tool.Name() != "arjun" {
		t.Errorf("expected tool name arjun, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, nil, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 0 {
		t.Errorf("expected no events, got %d", len(events))
	}
}
