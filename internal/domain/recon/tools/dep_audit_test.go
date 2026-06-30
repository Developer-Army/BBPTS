package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDepAuditTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "package.json") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"dependencies": {
					"jquery": "^3.4.1",
					"lodash": "4.17.15"
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &DepAuditTool{}
	if tool.Name() != "dep_audit" {
		t.Errorf("expected tool name dep_audit, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundJquery, foundLodash bool
	for _, ev := range events {
		pkg := ev.Properties["package"]
		if pkg == "jquery" {
			foundJquery = true
			if ev.Properties["cve"] != "CVE-2020-11022" {
				t.Errorf("expected jQuery CVE-2020-11022, got %s", ev.Properties["cve"])
			}
		}
		if pkg == "lodash" {
			foundLodash = true
			if ev.Properties["cve"] != "CVE-2020-8203" {
				t.Errorf("expected Lodash CVE-2020-8203, got %s", ev.Properties["cve"])
			}
		}
	}

	if !foundJquery || !foundLodash {
		t.Error("expected to audit and find vulnerable jquery and lodash dependencies")
	}
}
