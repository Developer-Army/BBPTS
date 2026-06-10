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
