package ownership

import (
	"encoding/json"
	"testing"
)

func TestOwnershipJSONSerialization(t *testing.T) {
	owner := Owner{
		ID:    1,
		Name:  "Security Operations",
		Email: "secops@acme-corp.io",
	}

	data, err := json.Marshal(owner)
	if err != nil {
		t.Fatalf("Failed to marshal Owner: %v", err)
	}

	var unmarshaled Owner
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal Owner: %v", err)
	}

	if unmarshaled.ID != owner.ID {
		t.Errorf("Expected ID %d, got %d", owner.ID, unmarshaled.ID)
	}
	if unmarshaled.Email != owner.Email {
		t.Errorf("Expected Email %q, got %q", owner.Email, unmarshaled.Email)
	}
}

func TestTeamJSONSerialization(t *testing.T) {
	managerID := int64(42)
	team := Team{
		ID:        10,
		Name:      "DevOps",
		ManagerID: &managerID,
	}

	data, err := json.Marshal(team)
	if err != nil {
		t.Fatalf("Failed to marshal Team: %v", err)
	}

	var unmarshaled Team
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal Team: %v", err)
	}

	if unmarshaled.ID != team.ID {
		t.Errorf("Expected ID %d, got %d", team.ID, unmarshaled.ID)
	}
	if *unmarshaled.ManagerID != *team.ManagerID {
		t.Errorf("Expected ManagerID %d, got %d", *team.ManagerID, *unmarshaled.ManagerID)
	}
}

func TestBusinessUnitJSONSerialization(t *testing.T) {
	directorID := int64(100)
	bu := BusinessUnit{
		ID:         5,
		Name:       "Engineering",
		DirectorID: &directorID,
	}

	data, err := json.Marshal(bu)
	if err != nil {
		t.Fatalf("Failed to marshal BusinessUnit: %v", err)
	}

	var unmarshaled BusinessUnit
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal BusinessUnit: %v", err)
	}

	if unmarshaled.ID != bu.ID {
		t.Errorf("Expected ID %d, got %d", bu.ID, unmarshaled.ID)
	}
}

func TestAssetOwnership_FirstClass(t *testing.T) {
	ao := AssetOwnership{
		AssetID: "subdomain:api.acme-corp.io",
	}

	if !ao.IsUnmanagedRisk() {
		t.Error("expected initial asset to be unmanaged risk")
	}

	chain := GenerateEscalationChain("alice@acme-corp.io", "API-Team", "bob@acme-corp.io", "director@acme-corp.io")
	err := ao.AssignAssetOwner(1, 10, 0.95, chain, "admin-1", "derived from DNS records")
	if err != nil {
		t.Fatalf("failed asset owner assignment: %v", err)
	}

	if ao.IsUnmanagedRisk() {
		t.Error("expected asset to be managed after owner assignment")
	}

	if ao.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %f", ao.Confidence)
	}

	if len(ao.EscalationPath) != 3 {
		t.Errorf("expected escalation path length 3, got %d", len(ao.EscalationPath))
	}

	if len(ao.AuditTrail) != 1 {
		t.Errorf("expected 1 audit log entry, got %d", len(ao.AuditTrail))
	}

	err = ao.AssignAssetOwner(1, 10, 1.5, chain, "admin-1", "invalid")
	if err == nil {
		t.Error("expected error for confidence > 1.0")
	}
}

func TestFindingOwnership_FirstClass(t *testing.T) {
	fo := FindingOwnership{
		FindingID: 101,
	}

	if !fo.IsUnmanagedRisk() {
		t.Error("expected initial finding to be unmanaged risk")
	}

	chain := []string{"security@acme-corp.io"}
	err := fo.AssignFindingOwner(2, 20, 0.8, chain, "scanner", "automatic alert routing")
	if err != nil {
		t.Fatalf("failed finding owner assignment: %v", err)
	}

	if fo.IsUnmanagedRisk() {
		t.Error("expected finding to be managed")
	}

	if len(fo.AuditTrail) != 1 {
		t.Errorf("expected 1 audit log entry, got %d", len(fo.AuditTrail))
	}
}
