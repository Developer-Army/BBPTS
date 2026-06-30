package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestCVECorrelateTool(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"vulnerabilities": [
				{
					"cveID": "CVE-2021-23017",
					"vendorProject": "NGINX",
					"product": "NGINX",
					"vulnerabilityName": "NGINX Resolver Out-of-Bounds Write Vulnerability",
					"shortDescription": "NGINX open source and commercial versions before 1.20.1 contain an out-of-bounds write."
				}
			]
		}`))
	}))
	defer server.Close()

	oldURL := cisaKevURL
	cisaKevURL = server.URL
	defer func() { cisaKevURL = oldURL }()

	_ = os.Remove(localKevCache)
	defer os.Remove(localKevCache)

	tmpDir, err := os.MkdirTemp("", "bbpts-cve-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "bbpts.db")
	store, err := storage.NewStorage("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to initialize SQLite storage: %v", err)
	}
	defer store.Close()

	target := "http://example.com"
	mockEv := recon.NewEvent(target, "httpx", "service", map[string]string{
		"server":       "nginx/1.18.0",
		"technologies": "nginx",
	})
	if err := store.SaveEvent(mockEv); err != nil {
		t.Fatalf("failed to save mock event: %v", err)
	}

	tool := &CVECorrelateTool{}
	if tool.Name() != "cve_correlate" {
		t.Errorf("expected tool name cve_correlate, got %s", tool.Name())
	}

	ctx := storage.WithStorage(context.Background(), store)
	events, err := tool.Run(ctx, &recon.ScanContext{}, []string{target}, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var foundCVE bool
	for _, ev := range events {
		if ev.Properties["cve"] == "CVE-2021-23017" {
			foundCVE = true
			if ev.Properties["severity"] != "critical" {
				t.Errorf("expected severity critical, got %s", ev.Properties["severity"])
			}
		}
	}

	if !foundCVE {
		t.Error("expected to correlate and detect CVE-2021-23017 vulnerability")
	}
}
