package recon

import (
	"context"
	"testing"
	"time"
)

func TestNewFingerprinter(t *testing.T) {
	fp := New()
	if fp == nil {
		t.Fatal("NewFingerprinter returned nil")
	}
	if fp.httpClient == nil {
		t.Error("httpClient not initialized")
	}
	if fp.timeout != 12*time.Second {
		t.Errorf("expected timeout 12s, got %v", fp.timeout)
	}
}

func TestFingerprinter_Fingerprint(t *testing.T) {
	fp := New()
	ctx := context.Background()

	tests := []struct {
		name   string
		target string
	}{
		{"with scheme", "https://acme-corp.io"},
		{"without scheme", "acme-corp.io"},
		{"with path", "https://acme-corp.io/test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fp.Fingerprint(ctx, tt.target)
			if result.Host != tt.target {
				t.Errorf("expected host %s, got %s", tt.target, result.Host)
			}

			if result.JARMHash != "" && len(result.JARMHash) < 8 {
				t.Error("JARM hash too short")
			}
		})
	}
}

func TestFingerprinter_FingerprintAll(t *testing.T) {
	fp := New()
	ctx := context.Background()

	targets := []string{"acme-corp.io", "test.com", "demo.com"}
	results := fp.FingerprintAll(ctx, targets, 2)

	if len(results) != len(targets) {
		t.Errorf("expected %d results, got %d", len(targets), len(results))
	}

	foundHosts := make(map[string]bool)
	for _, result := range results {
		foundHosts[result.Host] = true
	}

	for _, target := range targets {
		if !foundHosts[target] {
			t.Errorf("target %s not found in results", target)
		}
	}
}

func TestFingerprinter_FingerprintAll_ZeroConcurrency(t *testing.T) {
	fp := New()
	ctx := context.Background()

	targets := []string{"acme-corp.io"}
	results := fp.FingerprintAll(ctx, targets, 0)

	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

func TestClusterByJARM(t *testing.T) {
	results := []Result{
		{Host: "a.com", JARMHash: "hash1"},
		{Host: "b.com", JARMHash: "hash1"},
		{Host: "c.com", JARMHash: "hash2"},
		{Host: "d.com", JARMHash: ""},
	}

	clusters := ClusterByJARM(results)

	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(clusters))
	}

	if len(clusters["hash1"]) != 2 {
		t.Errorf("expected 2 hosts in hash1 cluster, got %d", len(clusters["hash1"]))
	}

	if len(clusters["hash2"]) != 1 {
		t.Errorf("expected 1 host in hash2 cluster, got %d", len(clusters["hash2"]))
	}
}

func TestClusterByFavicon(t *testing.T) {
	results := []Result{
		{Host: "a.com", FaviconHash: "fav1"},
		{Host: "b.com", FaviconHash: "fav1"},
		{Host: "c.com", FaviconHash: "fav2"},
		{Host: "d.com", FaviconHash: ""},
	}

	clusters := ClusterByFavicon(results)

	if len(clusters) != 2 {
		t.Errorf("expected 2 clusters, got %d", len(clusters))
	}

	if len(clusters["fav1"]) != 2 {
		t.Errorf("expected 2 hosts in fav1 cluster, got %d", len(clusters["fav1"]))
	}

	if len(clusters["fav2"]) != 1 {
		t.Errorf("expected 1 host in fav2 cluster, got %d", len(clusters["fav2"]))
	}
}

func TestClusterByJARM_Empty(t *testing.T) {
	results := []Result{}
	clusters := ClusterByJARM(results)

	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters, got %d", len(clusters))
	}
}

func TestClusterByFavicon_Empty(t *testing.T) {
	results := []Result{}
	clusters := ClusterByFavicon(results)

	if len(clusters) != 0 {
		t.Errorf("expected 0 clusters, got %d", len(clusters))
	}
}

func TestMin(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{5, 3, 3},
		{0, 0, 0},
		{-1, 1, -1},
	}

	for _, tt := range tests {
		result := min(tt.a, tt.b)
		if result != tt.expected {
			t.Errorf("min(%d, %d) = %d, expected %d", tt.a, tt.b, result, tt.expected)
		}
	}
}
