package storage

import (
	"path/filepath"
	"testing"
	"time"
)

func TestGraphAdvancedQueries(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts_graph.db")
	s, err := NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer s.Close()

	// 1. Setup mock nodes for unowned assets test
	// Save owned asset
	ownedID, err := s.SaveNode("target", "owned.acme.com", nil, "", "", 1.0)
	if err != nil {
		t.Fatalf("Failed to save node: %v", err)
	}
	// Save unowned asset
	unownedID, err := s.SaveNode("target", "unowned.acme.com", nil, "", "", 1.0)
	if err != nil {
		t.Fatalf("Failed to save node: %v", err)
	}
	// Save owner node
	ownerNodeID, err := s.SaveNode("owner", "alice@corp.com", nil, "", "", 1.0)
	if err != nil {
		t.Fatalf("Failed to save node: %v", err)
	}
	// Link owned asset to owner
	err = s.SaveEdge(ownedID, ownerNodeID, "owned_by_owner", 1.0, "")
	if err != nil {
		t.Fatalf("Failed to save edge: %v", err)
	}

	// Verify GetUnownedAssets
	unowned, err := s.GetUnownedAssets()
	if err != nil {
		t.Fatalf("GetUnownedAssets failed: %v", err)
	}
	if len(unowned) != 1 || unowned[0].ID != unownedID {
		t.Errorf("Expected 1 unowned node (ID %s), got %d: %v", unownedID, len(unowned), unowned)
	}

	// 2. Setup mock graph path for GetShortestAttackPath & GetBlastRadius
	// internet -> public-subdomain -> internal-service -> sensitive-db
	internetID, _ := s.SaveNode("target", "internet", nil, "", "", 1.0)
	pubSubID, _ := s.SaveNode("target", "pub.acme.com", nil, "", "", 1.0)
	intServID, _ := s.SaveNode("target", "int.acme.com", nil, "", "", 1.0)
	sensDbID, _ := s.SaveNode("target", "db.acme.com", nil, "", "", 1.0)

	_ = s.SaveEdge(internetID, pubSubID, "exposes", 1.0, "")
	_ = s.SaveEdge(pubSubID, intServID, "depends_on", 1.0, "")
	_ = s.SaveEdge(intServID, sensDbID, "hosts", 1.0, "")

	// GetShortestAttackPath
	path, err := s.GetShortestAttackPath(internetID, sensDbID, 5)
	if err != nil {
		t.Fatalf("GetShortestAttackPath failed: %v", err)
	}
	if len(path) != 3 {
		t.Errorf("Expected path length 3, got %d", len(path))
	}
	if path[0].SourceID != internetID || path[2].TargetID != sensDbID {
		t.Errorf("Path doesn't connect source to target correctly: %v", path)
	}

	// GetBlastRadius
	radius, err := s.GetBlastRadius(pubSubID, 3)
	if err != nil {
		t.Fatalf("GetBlastRadius failed: %v", err)
	}
	// Blast radius should contain int.acme.com and db.acme.com
	if len(radius) != 2 {
		t.Errorf("Expected blast radius of 2 nodes, got %d: %v", len(radius), radius)
	}

	// 3. Team overdue findings test
	teamID, _ := s.AddTeam("DevTeam")
	ownerID, _ := s.AddOwner("Bob", "bob@corp.com")
	
	// Create mock finding
	findingID, err := s.AddFindingForTest("Secret key exposed", "desc", "critical", "owned.acme.com")
	if err != nil {
		t.Fatalf("Failed to add finding: %v", err)
	}
	
	assignmentID, err := s.AssignFinding(findingID, &teamID, &ownerID, "critical")
	if err != nil {
		t.Fatalf("Failed to assign finding: %v", err)
	}
	
	// Make overdue
	err = s.ForceAssignmentOverdueForTest(assignmentID, 24*time.Hour)
	if err != nil {
		t.Fatalf("Failed to force assignment overdue: %v", err)
	}
	
	overdueMap, err := s.GetTeamOverdueFindings()
	if err != nil {
		t.Fatalf("GetTeamOverdueFindings failed: %v", err)
	}
	
	if len(overdueMap["DevTeam"]) != 1 {
		t.Errorf("Expected 1 overdue finding for DevTeam, got %d", len(overdueMap["DevTeam"]))
	}
}

func TestGraphPagination(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts_graph_pagination.db")
	s, err := NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer s.Close()

	// Save nodes
	id1, _ := s.SaveNode("target", "node1.acme.com", nil, "", "", 1.0)
	id2, _ := s.SaveNode("target", "node2.acme.com", nil, "", "", 1.0)
	id3, _ := s.SaveNode("target", "node3.acme.com", nil, "", "", 1.0)

	// Save edges
	_ = s.SaveEdge(id1, id2, "links", 1.0, "")
	_ = s.SaveEdge(id2, id3, "links", 1.0, "")

	// Test GetAllAssetNodes pagination
	nodes, err := s.GetAllAssetNodes(2, 0)
	if err != nil {
		t.Fatalf("GetAllAssetNodes with limit failed: %v", err)
	}
	if len(nodes) != 2 {
		t.Errorf("Expected 2 nodes, got %d", len(nodes))
	}

	nodes, err = s.GetAllAssetNodes(2, 2)
	if err != nil {
		t.Fatalf("GetAllAssetNodes with offset failed: %v", err)
	}
	if len(nodes) != 1 {
		t.Errorf("Expected 1 node, got %d", len(nodes))
	}

	// Test GetAllAssetEdges pagination
	edges, err := s.GetAllAssetEdges(1, 0)
	if err != nil {
		t.Fatalf("GetAllAssetEdges with limit failed: %v", err)
	}
	if len(edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(edges))
	}

	edges, err = s.GetAllAssetEdges(1, 1)
	if err != nil {
		t.Fatalf("GetAllAssetEdges with offset failed: %v", err)
	}
	if len(edges) != 1 {
		t.Errorf("Expected 1 edge, got %d", len(edges))
	}
}
