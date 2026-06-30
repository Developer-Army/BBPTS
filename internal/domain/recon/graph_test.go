package recon

import (
	"testing"
	"time"
)

func TestNewMemoryGraph(t *testing.T) {
	graph := NewMemoryGraph()
	if graph == nil {
		t.Fatal("NewMemoryGraph returned nil")
	}
	if graph.nodes == nil {
		t.Error("nodes map not initialized")
	}
	if graph.edges == nil {
		t.Error("edges slice not initialized")
	}
}

func TestMemoryGraph_AddNode(t *testing.T) {
	graph := NewMemoryGraph()

	node := &GraphNode{
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	graph.AddNode(node)

	if len(graph.nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(graph.nodes))
	}

	if node.ID == "" {
		t.Error("node ID should be auto-generated")
	}
}

func TestMemoryGraph_AddNode_WithID(t *testing.T) {
	graph := NewMemoryGraph()

	node := &GraphNode{
		ID:         "custom-id",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	graph.AddNode(node)

	if len(graph.nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(graph.nodes))
	}

	if node.ID != "custom-id" {
		t.Errorf("expected ID 'custom-id', got '%s'", node.ID)
	}
}

func TestMemoryGraph_AddNode_Duplicate(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{
		ID:         "test-id",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	node2 := &GraphNode{
		ID:         "test-id",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	graph.AddNode(node1)
	graph.AddNode(node2)

	if len(graph.nodes) != 1 {
		t.Errorf("expected 1 node (duplicate should not be added), got %d", len(graph.nodes))
	}
}

func TestMemoryGraph_AddEdge(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{
		ID:         "node1",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	node2 := &GraphNode{
		ID:         "node2",
		Type:       "Subdomain",
		Properties: map[string]string{"Value": "api.acme-corp.io"},
	}

	graph.AddNode(node1)
	graph.AddNode(node2)
	graph.AddEdge("node1", "node2", "RESOLVES_TO", 10)

	if len(graph.edges) != 1 {
		t.Errorf("expected 1 edge, got %d", len(graph.edges))
	}

	edge := graph.edges[0]
	if edge.SourceID != "node1" {
		t.Errorf("expected source 'node1', got '%s'", edge.SourceID)
	}
	if edge.TargetID != "node2" {
		t.Errorf("expected target 'node2', got '%s'", edge.TargetID)
	}
	if edge.Relation != "RESOLVES_TO" {
		t.Errorf("expected relation 'RESOLVES_TO', got '%s'", edge.Relation)
	}
	if edge.Weight != 10 {
		t.Errorf("expected weight 10, got %d", edge.Weight)
	}
}

func TestMemoryGraph_AddEdge_MissingSource(t *testing.T) {
	graph := NewMemoryGraph()

	node := &GraphNode{
		ID:         "node1",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	graph.AddNode(node)
	graph.AddEdge("node1", "nonexistent", "RESOLVES_TO", 10)

	if len(graph.edges) != 0 {
		t.Errorf("expected 0 edges (target doesn't exist), got %d", len(graph.edges))
	}
}

func TestMemoryGraph_AddEdge_MissingTarget(t *testing.T) {
	graph := NewMemoryGraph()

	node := &GraphNode{
		ID:         "node1",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	graph.AddNode(node)
	graph.AddEdge("nonexistent", "node1", "RESOLVES_TO", 10)

	if len(graph.edges) != 0 {
		t.Errorf("expected 0 edges (source doesn't exist), got %d", len(graph.edges))
	}
}

func TestMemoryGraph_FindPivots(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{
		ID:         "node1",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	node2 := &GraphNode{
		ID:         "node2",
		Type:       "Subdomain",
		Properties: map[string]string{"Value": "api.acme-corp.io"},
	}

	node3 := &GraphNode{
		ID:         "node3",
		Type:       "JS_File",
		Properties: map[string]string{"Value": "app.js"},
	}

	graph.AddNode(node1)
	graph.AddNode(node2)
	graph.AddNode(node3)

	graph.AddEdge("node1", "node2", "RESOLVES_TO", 10)
	graph.AddEdge("node1", "node3", "LOADS", 5)

	pivots := graph.FindPivots("node1")

	if len(pivots) != 2 {
		t.Errorf("expected 2 pivots, got %d", len(pivots))
	}
}

func TestMemoryGraph_FindPivots_NoEdges(t *testing.T) {
	graph := NewMemoryGraph()

	node := &GraphNode{
		ID:         "node1",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	graph.AddNode(node)
	pivots := graph.FindPivots("node1")

	if len(pivots) != 0 {
		t.Errorf("expected 0 pivots (no edges), got %d", len(pivots))
	}
}

func TestMemoryGraph_FindPivots_NonExistentNode(t *testing.T) {
	graph := NewMemoryGraph()

	pivots := graph.FindPivots("nonexistent")

	if len(pivots) != 0 {
		t.Errorf("expected 0 pivots (node doesn't exist), got %d", len(pivots))
	}
}

func TestMemoryGraph_FindPivots_DuplicateEdges(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{
		ID:         "node1",
		Type:       "Domain",
		Properties: map[string]string{"Value": "acme-corp.io"},
	}

	node2 := &GraphNode{
		ID:         "node2",
		Type:       "Subdomain",
		Properties: map[string]string{"Value": "api.acme-corp.io"},
	}

	graph.AddNode(node1)
	graph.AddNode(node2)

	graph.AddEdge("node1", "node2", "RESOLVES_TO", 10)
	graph.AddEdge("node1", "node2", "RESOLVES_TO", 10)

	pivots := graph.FindPivots("node1")

	if len(pivots) != 1 {
		t.Errorf("expected 1 unique pivot, got %d", len(pivots))
	}
}

func TestMemoryGraph_MultipleEdges(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{ID: "node1", Type: "Domain", Properties: map[string]string{"Value": "acme-corp.io"}}
	node2 := &GraphNode{ID: "node2", Type: "Subdomain", Properties: map[string]string{"Value": "api.acme-corp.io"}}
	node3 := &GraphNode{ID: "node3", Type: "JS_File", Properties: map[string]string{"Value": "app.js"}}

	graph.AddNode(node1)
	graph.AddNode(node2)
	graph.AddNode(node3)

	graph.AddEdge("node1", "node2", "RESOLVES_TO", 10)
	graph.AddEdge("node2", "node3", "LOADS", 5)

	pivots := graph.FindPivots("node1")
	if len(pivots) != 1 {
		t.Errorf("expected 1 pivot (1-degree search), got %d", len(pivots))
	}
}

func TestGraphNode_Properties(t *testing.T) {
	graph := NewMemoryGraph()

	node := &GraphNode{
		Type: "Domain",
		Properties: map[string]string{
			"Value":    "acme-corp.io",
			"Status":   "active",
			"Priority": "high",
		},
	}

	graph.AddNode(node)

	if len(node.Properties) != 3 {
		t.Errorf("expected 3 properties, got %d", len(node.Properties))
	}

	if node.Properties["Value"] != "acme-corp.io" {
		t.Errorf("expected property Value 'acme-corp.io', got '%s'", node.Properties["Value"])
	}
}

func TestMemoryGraph_PropagateRisk(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{ID: "subdomain", Type: "Subdomain", Confidence: 0.9}
	node2 := &GraphNode{ID: "js_file", Type: "JS_File", Confidence: 0.8}
	node3 := &GraphNode{ID: "secret_leak", Type: "Secret_Leak", Confidence: 1.0}

	graph.AddNode(node1)
	graph.AddNode(node2)
	graph.AddNode(node3)

	graph.edges = append(graph.edges, GraphEdge{SourceID: "subdomain", TargetID: "js_file", Relation: "LOADS", Weight: 80, Confidence: 0.9})
	graph.edges = append(graph.edges, GraphEdge{SourceID: "js_file", TargetID: "secret_leak", Relation: "EXPOSES", Weight: 100, Confidence: 1.0})

	initialRisk := map[string]float64{
		"secret_leak": 100.0,
	}

	propagated := graph.PropagateRisk(initialRisk)

	if propagated["secret_leak"] != 100.0 {
		t.Errorf("expected secret_leak risk to be 100.0, got %f", propagated["secret_leak"])
	}

	if propagated["js_file"] != 100.0 {
		t.Errorf("expected js_file risk to be 100.0, got %f", propagated["js_file"])
	}

	expectedRisk := 100.0 * 0.8 * 0.9 * 0.8
	if propagated["subdomain"] != expectedRisk {
		t.Errorf("expected subdomain risk to be %f, got %f", expectedRisk, propagated["subdomain"])
	}
}

func TestMemoryGraph_TimeDecay(t *testing.T) {
	graph := NewMemoryGraph()

	now := time.Now()
	node1 := &GraphNode{ID: "node1", Type: "Domain", LastSeen: now.Add(-48 * time.Hour), Confidence: 1.0}
	node2 := &GraphNode{ID: "node2", Type: "Subdomain", LastSeen: now.Add(-24 * time.Hour), Confidence: 1.0}

	graph.AddNode(node1)
	graph.AddNode(node2)

	graph.AddEdgeAdvanced("node1", "node2", "RESOLVES_TO", 10, 1.0, "system")
	graph.edges[0].LastSeen = now.Add(-72 * time.Hour)

	graph.ApplyTimeDecay(now, 1.0)

	if node1.Confidence >= 0.3 {
		t.Errorf("expected node1 confidence to decay, got %f", node1.Confidence)
	}

	if node2.Confidence >= 0.6 || node2.Confidence <= 0.4 {
		t.Errorf("expected node2 confidence to be around 0.5, got %f", node2.Confidence)
	}

	if graph.edges[0].Confidence >= 0.15 {
		t.Errorf("expected edge confidence to decay heavily, got %f", graph.edges[0].Confidence)
	}
}

func TestMemoryGraph_BlastRadiusPropagation(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{ID: "target", Type: "Target", BlastRadius: 50.0}
	node2 := &GraphNode{ID: "subdomain1", Type: "Subdomain", BlastRadius: 10.0}
	node3 := &GraphNode{ID: "subdomain2", Type: "Subdomain", BlastRadius: 20.0}

	graph.AddNode(node1)
	graph.AddNode(node2)
	graph.AddNode(node3)

	graph.AddEdge("target", "subdomain1", "exposes", 10)
	graph.AddEdge("subdomain1", "subdomain2", "loads", 10)

	totalBlast := graph.PropagateBlastRadius("target")

	expected := 60.0
	if totalBlast != expected {
		t.Errorf("expected blast radius %f, got %f", expected, totalBlast)
	}
}

func TestMemoryGraph_PathCostAndCheapestPath(t *testing.T) {
	graph := NewMemoryGraph()

	node1 := &GraphNode{ID: "A", Type: "Subdomain"}
	node2 := &GraphNode{ID: "B", Type: "Service"}
	node3 := &GraphNode{ID: "C", Type: "Database"}
	node4 := &GraphNode{ID: "D", Type: "CrownJewel"}

	graph.AddNode(node1)
	graph.AddNode(node2)
	graph.AddNode(node3)
	graph.AddNode(node4)

	graph.AddEdgeAdvanced("A", "B", "connects", 80, 1.0, "system")
	graph.AddEdgeAdvanced("B", "D", "connects", 50, 1.0, "system")
	graph.AddEdgeAdvanced("A", "C", "connects", 10, 1.0, "system")
	graph.AddEdgeAdvanced("C", "D", "connects", 20, 1.0, "system")

	path, cost := graph.GetCheapestAttackPath("A", "D")
	if cost != 30.0 {
		t.Errorf("expected cheapest path cost to be 30.0, got %f", cost)
	}

	if len(path) != 3 || path[0] != "A" || path[1] != "C" || path[2] != "D" {
		t.Errorf("expected cheapest path [A, C, D], got %v", path)
	}
}
