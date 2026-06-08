package assets

import (
	"testing"
)

func TestDetectDrift_NewAsset(t *testing.T) {
	newAsset := Asset{
		ID:   "asset-001",
		Name: "dev.acme-corp.io",
		Type: "subdomain",
	}

	drifts := DetectDrift(Asset{}, newAsset)
	if len(drifts) != 1 {
		t.Fatalf("Expected 1 drift event, got %d", len(drifts))
	}

	if drifts[0].ChangeType != "new_asset" {
		t.Errorf("Expected change type 'new_asset', got '%s'", drifts[0].ChangeType)
	}
}

func TestDetectDrift_ExistingAssetDrift(t *testing.T) {
	oldAsset := Asset{
		ID:          "asset-001",
		Name:        "dev.acme-corp.io",
		Type:        "subdomain",
		Status:      "active",
		Criticality: "medium",
	}

	newAsset := Asset{
		ID:          "asset-001",
		Name:        "dev.acme-corp.io",
		Type:        "service",
		Status:      "inactive",
		Criticality: "high",
	}

	drifts := DetectDrift(oldAsset, newAsset)
	if len(drifts) != 3 {
		t.Fatalf("Expected 3 drift events, got %d", len(drifts))
	}

	expectedTypes := map[string]bool{
		"type_change":       true,
		"status_drift":      true,
		"criticality_drift": true,
	}

	for _, d := range drifts {
		if !expectedTypes[d.ChangeType] {
			t.Errorf("Unexpected drift change type: %s", d.ChangeType)
		}
	}
}
