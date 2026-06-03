package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCTEMBasic(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts.db")
	s, err := NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer s.Close()

	// 1. Teams
	teamID, err := s.AddTeam("SecOps")
	if err != nil {
		t.Fatalf("AddTeam failed: %v", err)
	}
	team, err := s.GetTeam(teamID)
	if err != nil || team == nil || team.Name != "SecOps" {
		t.Fatalf("GetTeam failed: %v", err)
	}

	// 2. Owners
	ownerID, err := s.AddOwner("Alice", "alice@corp.com")
	if err != nil {
		t.Fatalf("AddOwner failed: %v", err)
	}
	owner, err := s.GetOwner(ownerID)
	if err != nil || owner == nil || owner.Email != "alice@corp.com" {
		t.Fatalf("GetOwner failed: %v", err)
	}

	// 3. Asset Ownership (SCD Type 2)
	assetID := "api.corp.com"
	err = s.SetAssetOwner(assetID, &ownerID, &teamID, "Initial assignment")
	if err != nil {
		t.Fatalf("SetAssetOwner failed: %v", err)
	}

	owners, err := s.GetAssetOwners(assetID)
	if err != nil || len(owners) != 1 {
		t.Fatalf("GetAssetOwners failed: %v, len: %d", err, len(owners))
	}
	if owners[0].OwnerID == nil || *owners[0].OwnerID != ownerID || owners[0].EndTime != nil {
		t.Errorf("Unexpected active ownership properties")
	}

	// Set new owner
	owner2ID, _ := s.AddOwner("Bob", "bob@corp.com")
	err = s.SetAssetOwner(assetID, &owner2ID, &teamID, "Ownership transfer to Bob")
	if err != nil {
		t.Fatalf("Second SetAssetOwner failed: %v", err)
	}

	owners, err = s.GetAssetOwners(assetID)
	if err != nil || len(owners) != 2 {
		t.Fatalf("Expected 2 ownership records, got %d", len(owners))
	}
	// Verify historical ordering (newest first because of ORDER BY start_time DESC)
	if *owners[0].OwnerID != owner2ID || owners[0].EndTime != nil {
		t.Errorf("Expected Bob as active owner")
	}
	if owners[0].ChangeReason != "Ownership transfer to Bob" {
		t.Errorf("Expected Bob ownership change reason, got: %s", owners[0].ChangeReason)
	}
	if *owners[1].OwnerID != ownerID || owners[1].EndTime == nil {
		t.Errorf("Expected Alice as closed/past owner")
	}
	if owners[1].ChangeReason != "Initial assignment" {
		t.Errorf("Expected Alice ownership change reason, got: %s", owners[1].ChangeReason)
	}

	// 4. SLA Policies & Escalation Rules
	policyID, err := s.AddSLAPolicy("Critical Findings Policy", "critical", 2)
	if err != nil {
		t.Fatalf("AddSLAPolicy failed: %v", err)
	}
	policy, err := s.GetSLAPolicy(policyID)
	if err != nil || policy == nil || policy.Severity != "critical" {
		t.Fatalf("GetSLAPolicy failed: %v", err)
	}

	ruleID, err := s.AddEscalationRule(policyID, 1, "slack", map[string]interface{}{"url": "https://hooks.slack.com/services/123"})
	if err != nil {
		t.Fatalf("AddEscalationRule failed: %v", err)
	}

	rules, err := s.GetEscalationRules(policyID)
	if err != nil || len(rules) != 1 || rules[0].ID != ruleID {
		t.Fatalf("GetEscalationRules failed: %v", err)
	}
	if rules[0].Properties["url"] != "https://hooks.slack.com/services/123" {
		t.Errorf("Expected rule properties matched")
	}

	rulesForSev, err := s.GetEscalationRulesForSeverity("critical")
	if err != nil || len(rulesForSev) != 1 {
		t.Fatalf("GetEscalationRulesForSeverity failed: %v", err)
	}

	// 5. Findings & Assignments
	// Insert dummy finding in db
	findingQuery := `
		INSERT INTO findings (title, description, severity, target, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	res, err := s.db.Exec(findingQuery, "Exposed Secret", "API key leaked in JS", "critical", assetID, "", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert mock finding: %v", err)
	}
	findingID, _ := res.LastInsertId()

	assignmentID, err := s.AssignFinding(findingID, &teamID, &owner2ID, "critical")
	if err != nil {
		t.Fatalf("AssignFinding failed: %v", err)
	}

	// Update finding assignment status and verify overdue query
	err = s.UpdateAssignmentStatus(assignmentID, "remediating")
	if err != nil {
		t.Fatalf("UpdateAssignmentStatus failed: %v", err)
	}

	// Override due_at to make it overdue for testing
	_, err = s.db.Exec("UPDATE finding_assignments SET due_at = ? WHERE id = ?", time.Now().UTC().Add(-24*time.Hour), assignmentID)
	if err != nil {
		t.Fatalf("Failed to force assignment overdue: %v", err)
	}

	overdue, err := s.GetOverdueAssignments()
	if err != nil || len(overdue) != 1 {
		t.Fatalf("GetOverdueAssignments failed: %v, len: %d", err, len(overdue))
	}
	if overdue[0].AssignmentID != assignmentID || overdue[0].Status != "Acknowledged" {
		t.Errorf("Unexpected overdue assignment properties: got status %s, expected Acknowledged", overdue[0].Status)
	}

	// Verify audit trail status history
	history, err := s.GetFindingStatusHistory(findingID)
	if err != nil {
		t.Fatalf("GetFindingStatusHistory failed: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("Expected 2 history records, got %d", len(history))
	}
	if history[0].OldStatus != "Discovered" || history[0].NewStatus != "Assigned" {
		t.Errorf("First transition mismatch: %s -> %s", history[0].OldStatus, history[0].NewStatus)
	}
	if history[1].OldStatus != "Assigned" || history[1].NewStatus != "Acknowledged" {
		t.Errorf("Second transition mismatch: %s -> %s", history[1].OldStatus, history[1].NewStatus)
	}

	// 6. Graph Mirroring verification
	// Check that target node is linked to Bob (owner2ID) and team
	assetNodeID := GenerateNodeID("target", assetID, "")
	edges, err := s.GetGraphPaths(assetNodeID, 3)
	if err != nil {
		t.Fatalf("GetGraphPaths failed: %v", err)
	}
	if len(edges) < 2 {
		t.Fatalf("Expected graph edges representing ownership, got %d", len(edges))
	}

	foundOwnerLink := false
	foundTeamLink := false
	for _, edge := range edges {
		if edge.Relation == "owned_by_owner" {
			foundOwnerLink = true
		}
		if edge.Relation == "owned_by_team" {
			foundTeamLink = true
		}
	}
	if !foundOwnerLink || !foundTeamLink {
		t.Errorf("Ownership links missing in graph path: owner=%t, team=%t", foundOwnerLink, foundTeamLink)
	}
}

func TestSLAMatching(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts_sla.db")
	s, err := NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer s.Close()

	// Add a generic policy: duration 14 days
	_, _ = s.AddSLAPolicyExt("Generic Critical Policy", "critical", 14, "", "", "", "")

	// Add a more specific policy matching asset_class = "Payment System": duration 2 days
	_, _ = s.AddSLAPolicyExt("Critical Payment Policy", "critical", 2, "Payment System", "", "", "")

	// Add another specific policy matching business_unit = "Finance": duration 5 days
	_, _ = s.AddSLAPolicyExt("Finance Critical Policy", "critical", 5, "", "Finance", "", "")

	// Match payment system policy
	policy1, err := s.GetMatchingSLAPolicy("critical", "Payment System", "Marketing", "production", "main")
	if err != nil || policy1 == nil {
		t.Fatalf("GetMatchingSLAPolicy failed: %v", err)
	}
	if policy1.DurationDays != 2 {
		t.Errorf("Expected duration 2 for Payment System, got %d", policy1.DurationDays)
	}

	// Match finance policy
	policy2, err := s.GetMatchingSLAPolicy("critical", "API Endpoint", "Finance", "production", "main")
	if err != nil || policy2 == nil {
		t.Fatalf("GetMatchingSLAPolicy failed: %v", err)
	}
	if policy2.DurationDays != 5 {
		t.Errorf("Expected duration 5 for Finance, got %d", policy2.DurationDays)
	}

	// Match generic policy
	policy3, err := s.GetMatchingSLAPolicy("critical", "API Endpoint", "Marketing", "production", "main")
	if err != nil || policy3 == nil {
		t.Fatalf("GetMatchingSLAPolicy failed: %v", err)
	}
	if policy3.DurationDays != 14 {
		t.Errorf("Expected duration 14 for generic matching, got %d", policy3.DurationDays)
	}
}

func TestCTEMStateTransitions(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts_ctem_transitions.db")
	s, err := NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer s.Close()

	// Add dummy finding
	res, err := s.db.Exec(`
		INSERT INTO findings (title, description, severity, target, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, "Test Title", "Test Desc", "high", "test.corp.com", "", time.Now().UTC())
	if err != nil {
		t.Fatalf("Failed to insert mock finding: %v", err)
	}
	findingID, _ := res.LastInsertId()

	teamID, _ := s.AddTeam("Team")
	ownerID, _ := s.AddOwner("Alice", "alice@corp.com")

	assignmentID, err := s.AssignFinding(findingID, &teamID, &ownerID, "high")
	if err != nil {
		t.Fatalf("AssignFinding failed: %v", err)
	}

	// Initial status is Assigned.
	// Try invalid transition: Assigned -> Verified
	err = s.UpdateAssignmentStatus(assignmentID, "Verified")
	if err == nil {
		t.Errorf("Expected error for invalid transition Assigned -> Verified, got nil")
	}

	// Try valid transition: Assigned -> Acknowledged (remediating)
	err = s.UpdateAssignmentStatus(assignmentID, "remediating")
	if err != nil {
		t.Errorf("Unexpected error for valid transition Assigned -> Acknowledged: %v", err)
	}

	// Try valid transition: Acknowledged -> Remediated
	err = s.UpdateAssignmentStatus(assignmentID, "Remediated")
	if err != nil {
		t.Errorf("Unexpected error for valid transition Acknowledged -> Remediated: %v", err)
	}

	// Try valid transition: Remediated -> Verified
	err = s.UpdateAssignmentStatus(assignmentID, "Verified")
	if err != nil {
		t.Errorf("Unexpected error for valid transition Remediated -> Verified: %v", err)
	}

	// Try invalid transition: Verified -> Acknowledged
	err = s.UpdateAssignmentStatus(assignmentID, "Acknowledged")
	if err == nil {
		t.Errorf("Expected error for invalid transition Verified -> Acknowledged, got nil")
	}

	// Try valid transition: Verified -> Reopened
	err = s.UpdateAssignmentStatus(assignmentID, "Reopened")
	if err != nil {
		t.Errorf("Unexpected error for valid transition Verified -> Reopened: %v", err)
	}
}

