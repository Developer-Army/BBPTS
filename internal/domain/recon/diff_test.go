package recon

import (
	"testing"
	"time"
)

func TestNewDiffStore(t *testing.T) {
	store := NewDiffStore()
	if store == nil {
		t.Fatal("NewDiffStore returned nil")
	}
	if store.store == nil {
		t.Error("store map not initialized")
	}
}

func TestDiffStore_AnalyzeChanges_NewTargets(t *testing.T) {
	store := NewDiffStore()

	currentWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash1"},
		{Type: "subdomain", Value: "api.acme-corp.io", Hash: "hash2"},
	}

	result := store.AnalyzeChanges(currentWave)

	if len(result.NewTargets) != 2 {
		t.Errorf("expected 2 new targets, got %d", len(result.NewTargets))
	}

	if len(result.Changed) != 0 {
		t.Errorf("expected 0 changed targets, got %d", len(result.Changed))
	}
}

func TestDiffStore_AnalyzeChanges_ExistingUnchanged(t *testing.T) {
	store := NewDiffStore()

	// First wave
	firstWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash1"},
	}
	store.AnalyzeChanges(firstWave)

	// Second wave with same hash
	secondWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash1"},
	}
	result := store.AnalyzeChanges(secondWave)

	if len(result.NewTargets) != 0 {
		t.Errorf("expected 0 new targets, got %d", len(result.NewTargets))
	}

	if len(result.Changed) != 0 {
		t.Errorf("expected 0 changed targets, got %d", len(result.Changed))
	}
}

func TestDiffStore_AnalyzeChanges_Changed(t *testing.T) {
	store := NewDiffStore()

	// First wave
	firstWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash1"},
	}
	store.AnalyzeChanges(firstWave)

	// Second wave with different hash
	secondWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash2"},
	}
	result := store.AnalyzeChanges(secondWave)

	if len(result.NewTargets) != 0 {
		t.Errorf("expected 0 new targets, got %d", len(result.NewTargets))
	}

	if len(result.Changed) != 1 {
		t.Errorf("expected 1 changed target, got %d", len(result.Changed))
	}
}

func TestDiffStore_AnalyzeChanges_EmptyHash(t *testing.T) {
	store := NewDiffStore()

	// First wave with hash
	firstWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash1"},
	}
	store.AnalyzeChanges(firstWave)

	// Second wave with empty hash (should not be detected as change)
	secondWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: ""},
	}
	result := store.AnalyzeChanges(secondWave)

	if len(result.Changed) != 0 {
		t.Errorf("expected 0 changed targets when hash is empty, got %d", len(result.Changed))
	}
}

func TestDiffStore_AnalyzeChanges_Mixed(t *testing.T) {
	store := NewDiffStore()

	// First wave
	firstWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash1"},
		{Type: "subdomain", Value: "api.acme-corp.io", Hash: "hash2"},
	}
	store.AnalyzeChanges(firstWave)

	// Second wave with new and changed
	secondWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash3"},   // changed
		{Type: "subdomain", Value: "api.acme-corp.io", Hash: "hash2"},          // unchanged
		{Type: "endpoint", Value: "https://acme-corp.io/admin", Hash: "hash4"}, // new
	}
	result := store.AnalyzeChanges(secondWave)

	if len(result.NewTargets) != 1 {
		t.Errorf("expected 1 new target, got %d", len(result.NewTargets))
	}

	if len(result.Changed) != 1 {
		t.Errorf("expected 1 changed target, got %d", len(result.Changed))
	}
}

func TestCalculateHash(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{"non-empty", "test content", "not empty"},
		{"empty", "", ""},
		{"whitespace only", "   ", ""},
		{"different content", "different content", "not empty"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CalculateHash(tt.content)
			if tt.expected == "" && result != "" {
				t.Errorf("expected empty hash, got %s", result)
			}
			if tt.expected != "" && result == "" {
				t.Errorf("expected non-empty hash, got empty")
			}
		})
	}
}

func TestCalculateHash_Consistency(t *testing.T) {
	content := "test content"
	hash1 := CalculateHash(content)
	hash2 := CalculateHash(content)

	if hash1 != hash2 {
		t.Errorf("hashes should be consistent: %s != %s", hash1, hash2)
	}
}

func TestArtifact_Timestamps(t *testing.T) {
	store := NewDiffStore()

	before := time.Now()
	currentWave := []Artifact{
		{Type: "endpoint", Value: "https://acme-corp.io/api", Hash: "hash1"},
	}
	result := store.AnalyzeChanges(currentWave)
	after := time.Now()

	if len(result.NewTargets) != 1 {
		t.Fatal("expected 1 new target")
	}

	artifact := result.NewTargets[0]
	if artifact.FirstSeen.Before(before) || artifact.FirstSeen.After(after) {
		t.Error("FirstSeen timestamp not within expected range")
	}
	if artifact.LastSeen.Before(before) || artifact.LastSeen.After(after) {
		t.Error("LastSeen timestamp not within expected range")
	}
}

func TestDiffStore_AnalyzeChanges_EmptyWave(t *testing.T) {
	store := NewDiffStore()

	result := store.AnalyzeChanges([]Artifact{})

	if len(result.NewTargets) != 0 {
		t.Errorf("expected 0 new targets, got %d", len(result.NewTargets))
	}

	if len(result.Changed) != 0 {
		t.Errorf("expected 0 changed targets, got %d", len(result.Changed))
	}
}
