package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMobileReconTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "AndroidManifest.xml") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
<manifest>
  <application>
    <activity>
      <intent-filter>
        <data android:scheme="bbpts" android:host="triage" />
      </intent-filter>
    </activity>
  </application>
  <meta-data android:name="api_key" android:value="firebase_key_1234567890" />
</manifest>`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	tool := &MobileReconTool{}
	if tool.Name() != "mobile_recon" {
		t.Errorf("expected tool name mobile_recon, got %s", tool.Name())
	}

	events, err := tool.Run(context.Background(), &recon.ScanContext{}, []string{server.URL}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundDeepLink, foundSecret bool
	for _, ev := range events {
		if ev.Type == "discovery" && ev.Properties["type"] == "mobile_deep_link" {
			foundDeepLink = true
			if !strings.Contains(ev.Properties["deep_links"], "bbpts") {
				t.Errorf("expected deep_links bbpts, got %s", ev.Properties["deep_links"])
			}
		}
		if ev.Type == "vulnerability" && ev.Properties["vuln_name"] == "Hardcoded Secrets in Exposed Mobile App Resource" {
			foundSecret = true
		}
	}

	if !foundDeepLink {
		t.Error("expected to discover mobile deep link scheme")
	}
	if !foundSecret {
		t.Error("expected to discover hardcoded secrets in manifest file")
	}
}
