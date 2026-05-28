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
	err = s.SetAssetOwner(assetID, &ownerID, &teamID)
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
	err = s.SetAssetOwner(assetID, &owner2ID, &teamID)
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
	if *owners[1].OwnerID != ownerID || owners[1].EndTime == nil {
		t.Errorf("Expected Alice as closed/past owner")
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
	if overdue[0].AssignmentID != assignmentID || overdue[0].Status != "remediating" {
		t.Errorf("Unexpected overdue assignment properties")
	}

	// 6. Graph Mirroring verification
	// Check that target node is linked to Bob (owner2ID) and team
	assetNodeID := GenerateNodeID("target", assetID)
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
