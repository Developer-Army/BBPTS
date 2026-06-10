package assets

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAssetJSONSerialization(t *testing.T) {
	now := time.Now().UTC()
	ownerID := int64(100)
	asset := Asset{
		ID:          "asset-123",
		Type:        "subdomain",
		Name:        "api.acme-corp.io",
		Criticality: "high",
		Environment: "production",
		OwnerID:     &ownerID,
		Confidence:  0.95,
		FirstSeen:   now,
		LastSeen:    now,
		Status:      "active",
	}

	data, err := json.Marshal(asset)
	if err != nil {
		t.Fatalf("Failed to marshal Asset: %v", err)
	}

	var unmarshaled Asset
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal Asset: %v", err)
	}

	if unmarshaled.ID != asset.ID {
		t.Errorf("Expected ID %q, got %q", asset.ID, unmarshaled.ID)
	}
	if *unmarshaled.OwnerID != *asset.OwnerID {
		t.Errorf("Expected OwnerID %d, got %d", *asset.OwnerID, *unmarshaled.OwnerID)
	}
	if !unmarshaled.FirstSeen.Equal(asset.FirstSeen) {
		t.Errorf("Expected FirstSeen %v, got %v", asset.FirstSeen, unmarshaled.FirstSeen)
	}
}
