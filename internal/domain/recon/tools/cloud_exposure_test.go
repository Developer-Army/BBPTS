package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCloudExposureTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "credentials") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &CloudExposureTool{}
	if tool.Name() != "cloud_exposure" {
		t.Errorf("expected tool name cloud_exposure, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}

	ev := events[0]
	if ev.Properties["vuln_name"] != "Exposed Cloud Credentials File" {
		t.Errorf("expected vuln name, got %s", ev.Properties["vuln_name"])
	}
}
