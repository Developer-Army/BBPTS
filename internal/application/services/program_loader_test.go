package services

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProgramLoader_HackerOne(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/hackers/programs/shopify" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"data": {
					"attributes": {
						"name": "Shopify",
						"offers_bounties": true
					}
				}
			}`))
			return
		}
		if r.URL.Path == "/v1/hackers/programs/shopify/structured_scopes" {
			w.WriteHeader(http.StatusOK)

			_, _ = w.Write([]byte(`{
				"data": [
					{
						"attributes": {
							"asset_identifier": "*.shopify.com",
							"asset_type": "url",
							"eligible_for_bounty": true,
							"eligible_for_submission": true
						}
					},
					{
						"attributes": {
							"asset_identifier": "help.shopify.com",
							"asset_type": "url",
							"eligible_for_bounty": false,
							"eligible_for_submission": false
						}
					}
				],
				"links": {
					"next": ""
				}
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := ProgramLoaderConfig{
		H1Username: "testuser",
		H1Token:    "testtoken",
	}
	loader := NewProgramLoader(cfg)
	loader.h1Base = server.URL + "/v1/hackers"

	tmpDir, err := os.MkdirTemp("", "bbpts-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	scopePath := filepath.Join(tmpDir, "scope_shopify.txt")
	targetsPath := filepath.Join(tmpDir, "targets_shopify.txt")
	configPath := filepath.Join(tmpDir, "program_shopify.json")

	profile, err := loader.fetchHackerOne("shopify")
	if err != nil {
		t.Fatalf("failed to fetch HackerOne program: %v", err)
	}

	if profile.Name != "Shopify" {
		t.Errorf("expected program name Shopify, got %s", profile.Name)
	}
	if !profile.OfferBounty {
		t.Errorf("expected OfferBounty to be true")
	}
	if len(profile.InScope) != 1 || profile.InScope[0] != "*.shopify.com" {
		t.Errorf("unexpected in-scope: %v", profile.InScope)
	}
	if len(profile.OutOfScope) != 1 || profile.OutOfScope[0] != "help.shopify.com" {
		t.Errorf("unexpected out-of-scope: %v", profile.OutOfScope)
	}
	if len(profile.BountyTargets) != 1 || profile.BountyTargets[0] != "*.shopify.com" {
		t.Errorf("unexpected bounty targets: %v", profile.BountyTargets)
	}

	if err := profile.WriteScopeFile(scopePath); err != nil {
		t.Fatalf("failed to write scope file: %v", err)
	}
	if err := profile.WriteTargetsFile(targetsPath); err != nil {
		t.Fatalf("failed to write targets file: %v", err)
	}
	if err := profile.WriteConfigPatch(configPath); err != nil {
		t.Fatalf("failed to write config patch: %v", err)
	}

	scopeData, err := os.ReadFile(scopePath)
	if err != nil {
		t.Fatalf("failed to read scope file: %v", err)
	}
	if !strings.HasPrefix(string(scopeData), "# BBPTS scope file") {
		t.Errorf("scope file has invalid prefix")
	}
}

func TestProgramLoader_Bugcrowd(t *testing.T) {

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.bugcrowd+json")
		if r.URL.Path == "/programs" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"data": [
					{
						"id": "tesla-uuid",
						"type": "program",
						"attributes": {
							"name": "Tesla",
							"code": "tesla",
							"offers_bounty": true
						},
						"relationships": {
							"current_brief": {
								"data": {
									"id": "brief-uuid",
									"type": "program_brief"
								}
							}
						}
					}
				],
				"included": [
					{
						"id": "brief-uuid",
						"type": "program_brief",
						"relationships": {
							"target_groups": {
								"data": [
									{
										"id": "tg-in-scope",
										"type": "target_group"
									},
									{
										"id": "tg-out-scope",
										"type": "target_group"
									}
								]
							}
						}
					},
					{
						"id": "tg-in-scope",
						"type": "target_group",
						"attributes": {
							"name": "In Scope Web",
							"in_scope": true,
							"bounty": true
						},
						"relationships": {
							"targets": {
								"data": [
									{
										"id": "target-1",
										"type": "target"
									}
								]
							}
						}
					},
					{
						"id": "tg-out-scope",
						"type": "target_group",
						"attributes": {
							"name": "Out of Scope Web",
							"in_scope": false,
							"bounty": false
						},
						"relationships": {
							"targets": {
								"data": [
									{
										"id": "target-2",
										"type": "target"
									}
								]
							}
						}
					},
					{
						"id": "target-1",
						"type": "target",
						"attributes": {
							"name": "https://*.tesla.com",
							"category": "website"
						}
					},
					{
						"id": "target-2",
						"type": "target",
						"attributes": {
							"name": "http://dev.tesla.com/test",
							"category": "website"
						}
					}
				]
			}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := ProgramLoaderConfig{
		BCToken: "testtoken",
	}
	loader := NewProgramLoader(cfg)
	loader.bcBase = server.URL

	profile, err := loader.fetchBugcrowd("tesla")
	if err != nil {
		t.Fatalf("failed to fetch Bugcrowd program: %v", err)
	}

	if profile.Name != "Tesla" {
		t.Errorf("expected program name Tesla, got %s", profile.Name)
	}
	if len(profile.InScope) != 1 || profile.InScope[0] != "*.tesla.com" {
		t.Errorf("unexpected in-scope: %v", profile.InScope)
	}
	if len(profile.OutOfScope) != 1 || profile.OutOfScope[0] != "dev.tesla.com" {
		t.Errorf("unexpected out-of-scope: %v", profile.OutOfScope)
	}
	if len(profile.BountyTargets) != 1 || profile.BountyTargets[0] != "*.tesla.com" {
		t.Errorf("unexpected bounty targets: %v", profile.BountyTargets)
	}
}

func TestCleanTargetName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://*.shopify.com", "*.shopify.com"},
		{"http://help.shopify.com/path/index.html", "help.shopify.com"},
		{"192.168.1.1", "192.168.1.1"},
		{"192.168.1.0/24", "192.168.1.0/24"},
		{"*.shopify.com", "*.shopify.com"},
		{"shopify.com:8443", "shopify.com"},
	}

	for _, tt := range tests {
		got := cleanTargetName(tt.input)
		if got != tt.expected {
			t.Errorf("cleanTargetName(%q) = %q; expected %q", tt.input, got, tt.expected)
		}
	}
}

func TestProgramLoader_CacheTTL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bbpts-cache-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	filePath := filepath.Join(tmpDir, "test_file.txt")
	if err := os.WriteFile(filePath, []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	loader := NewProgramLoader(ProgramLoaderConfig{})

	if loader.shouldRefresh(filePath) {
		t.Errorf("expected shouldRefresh to be false for new file")
	}

	oldTime := time.Now().Add(-7 * time.Hour)
	if err := os.Chtimes(filePath, oldTime, oldTime); err != nil {
		t.Fatalf("failed to change file times: %v", err)
	}

	if !loader.shouldRefresh(filePath) {
		t.Errorf("expected shouldRefresh to be true for 7 hour old file")
	}

	if !loader.shouldRefresh(filepath.Join(tmpDir, "does_not_exist.txt")) {
		t.Errorf("expected shouldRefresh to be true for non-existent file")
	}
}
