package analyze

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func TestRecommendationEngine(t *testing.T) {

	targetNode := storage.AssetNode{
		ID:         "target_node_id",
		NodeType:   "target",
		Value:      "admin.example.com",
		Properties: json.RawMessage(`{}`),
		Confidence: 1.0,
	}

	endpointNode := storage.AssetNode{
		ID:         "endpoint_node_id",
		NodeType:   "endpoint",
		Value:      "http://admin.example.com/login",
		Properties: json.RawMessage(`{}`),
		Confidence: 1.0,
	}

	vulnNode := storage.AssetNode{
		ID:         "vuln_node_id",
		NodeType:   "vulnerability",
		Value:      "Critical CVE",
		Properties: json.RawMessage(`{"severity": "critical"}`),
		Confidence: 1.0,
	}

	serviceNode := storage.AssetNode{
		ID:         "service_node_id",
		NodeType:   "service",
		Value:      "admin.example.com:443",
		Properties: json.RawMessage(`{"waf": "none"}`),
		Confidence: 1.0,
	}

	nodes := []storage.AssetNode{targetNode, endpointNode, vulnNode, serviceNode}

	edges := []storage.AssetEdge{
		{
			SourceID: "target_node_id",
			TargetID: "service_node_id",
			Relation: "exposes_service",
		},
		{
			SourceID: "target_node_id",
			TargetID: "endpoint_node_id",
			Relation: "has_endpoint",
		},
		{
			SourceID: "target_node_id",
			TargetID: "vuln_node_id",
			Relation: "is_vulnerable_to",
		},
	}

	recs := RecommendTargets(nodes, edges)
	if len(recs) == 0 {
		t.Fatal("Expected at least one target recommendation")
	}

	rec := recs[0]
	if rec.AssetID != "admin.example.com" {
		t.Errorf("Expected recommended target admin.example.com, got %s", rec.AssetID)
	}

	hasWAFJustification := false
	hasCVEJustification := false
	for _, w := range rec.Why {
		if w == "✓ No WAF" {
			hasWAFJustification = true
		}
		if w == "✓ Critical CVE" {
			hasCVEJustification = true
		}
	}

	if !hasWAFJustification {
		t.Error("Expected '✓ No WAF' justification")
	}
	if !hasCVEJustification {
		t.Error("Expected '✓ Critical CVE' justification")
	}

	paths := GetAttackPaths(nodes, edges)
	if len(paths) == 0 {
		t.Fatal("Expected at least one attack path")
	}

	ranked := RankAttackPaths(paths)
	if len(ranked) == 0 {
		t.Fatal("Expected ranked paths")
	}

	if ranked[0].Score < 50 {
		t.Errorf("Expected path score >= 50, got %f", ranked[0].Score)
	}

	radius, err := CalculateBlastRadius("target_node_id", edges, nodes)
	if err != nil {
		t.Fatalf("Blast radius failed: %v", err)
	}

	if len(radius) != 3 {
		t.Errorf("Expected blast radius to contain 3 elements, got %d: %v", len(radius), radius)
	}
}

func TestRiskPropagation(t *testing.T) {

	apiNode := storage.AssetNode{
		ID:       "api_node",
		NodeType: "target",
		Value:    "api.example.com",
	}

	paymentNode := storage.AssetNode{
		ID:       "payment_node",
		NodeType: "target",
		Value:    "payment.example.com",
	}

	revenueNode := storage.AssetNode{
		ID:       "revenue_node",
		NodeType: "target",
		Value:    "revenue.example.com",
	}

	nodes := []storage.AssetNode{apiNode, paymentNode, revenueNode}

	edges := []storage.AssetEdge{
		{SourceID: "api_node", TargetID: "payment_node"},
		{SourceID: "payment_node", TargetID: "revenue_node"},
	}

	riskMap := PropagateRisk(nodes, edges)

	if riskMap["api_node"] < 60 {
		t.Errorf("Expected api_node risk >= 60, got %f", riskMap["api_node"])
	}

	if riskMap["payment_node"] < 100 {
		t.Errorf("Expected payment_node risk >= 100, got %f", riskMap["payment_node"])
	}

	expectedPropagatedRisk := 70.0
	if riskMap["revenue_node"] != expectedPropagatedRisk {
		t.Errorf("Expected revenue_node risk to be propagated to %f, got %f", expectedPropagatedRisk, riskMap["revenue_node"])
	}

	recs := RecommendTargets(nodes, edges)
	var revenueTarget *InvestigationTarget
	for i := range recs {
		if recs[i].AssetID == "revenue.example.com" {
			revenueTarget = &recs[i]
		}
	}
	if revenueTarget == nil {
		t.Fatal("Expected revenue target in recommendations")
	}

	hasPropagatedReason := false
	for _, w := range revenueTarget.Why {
		if strings.Contains(w, "Propagated Dependency Risk") {
			hasPropagatedReason = true
		}
	}
	if !hasPropagatedReason {
		t.Errorf("Expected 'Propagated Dependency Risk' why reason, got %v", revenueTarget.Why)
	}
}
