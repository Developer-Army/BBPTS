package findings

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEvidenceJSONSerialization(t *testing.T) {
	now := time.Now().UTC()
	evidence := Evidence{
		ID:          "ev-1",
		AssetID:     "asset-1",
		Source:      "subfinder",
		Confidence:  0.9,
		CollectedAt: now,
		RawData:     []byte(`{"domain":"test.com"}`),
		Hash:        "abcdef123456",
	}

	data, err := json.Marshal(evidence)
	if err != nil {
		t.Fatalf("Failed to marshal Evidence: %v", err)
	}

	var unmarshaled Evidence
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal Evidence: %v", err)
	}

	if unmarshaled.ID != evidence.ID {
		t.Errorf("Expected ID %q, got %q", evidence.ID, unmarshaled.ID)
	}
	if unmarshaled.AssetID != evidence.AssetID {
		t.Errorf("Expected AssetID %q, got %q", evidence.AssetID, unmarshaled.AssetID)
	}
	if !unmarshaled.CollectedAt.Equal(evidence.CollectedAt) {
		t.Errorf("Expected CollectedAt %v, got %v", evidence.CollectedAt, unmarshaled.CollectedAt)
	}
}

func TestFindingJSONSerialization(t *testing.T) {
	finding := Finding{
		ID:            101,
		AssetID:       "asset-1",
		RiskScore:     85,
		Confidence:    90,
		EvidenceIDs:   []string{"ev-1", "ev-2"},
		WorkflowState: "Discovered",
	}

	data, err := json.Marshal(finding)
	if err != nil {
		t.Fatalf("Failed to marshal Finding: %v", err)
	}

	var unmarshaled Finding
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal Finding: %v", err)
	}

	if unmarshaled.ID != finding.ID {
		t.Errorf("Expected ID %d, got %d", finding.ID, unmarshaled.ID)
	}
	if len(unmarshaled.EvidenceIDs) != len(finding.EvidenceIDs) {
		t.Errorf("Expected %d evidence IDs, got %d", len(finding.EvidenceIDs), len(unmarshaled.EvidenceIDs))
	}
}
