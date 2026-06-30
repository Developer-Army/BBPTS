package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSourceMapTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".js") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("console.log('hello');\n//# sourceMappingURL=main.js.map"))
			return
		}

		if strings.HasSuffix(r.URL.Path, ".map") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"version": 3,
				"sources": ["src/components/AdminPanel.vue", "src/utils/api.js"],
				"sourcesContent": [
					"// TODO: check bypass RBAC credentials\nconst password = 'SecretPassword123';\nconsole.log(password);",
					"const url = '/api/v2/admin/delete';\naxios.get(url);"
				]
			}`))
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &SourceMapTool{}
	if tool.Name() != "source_map" {
		t.Errorf("expected tool name source_map, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL + "/main.js"}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundSecret, foundEndpoint, foundComment bool
	for _, ev := range events {
		switch ev.Type {
		case "vulnerability":
			if ev.Properties["vuln_name"] == "Exposed Secret in Source Map" {
				foundSecret = true
			}
		case "api_endpoint":
			if ev.Target == "/api/v2/admin/delete" {
				foundEndpoint = true
			}
		case "discovery":
			if ev.Properties["type"] == "source_map_comment" {
				foundComment = true
			}
		}
	}

	if !foundSecret {
		t.Error("expected to find Exposed Secret in Source Map vulnerability")
	}
	if !foundEndpoint {
		t.Error("expected to find /api/v2/admin/delete endpoint")
	}
	if !foundComment {
		t.Error("expected to find source map comment discovery event")
	}
}
