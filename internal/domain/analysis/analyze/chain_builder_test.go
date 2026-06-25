package analyze

import (
	"encoding/json"
	"testing"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

func TestFindVulnerabilityChains(t *testing.T) {
	// Setup nodes
	targetNode := storage.AssetNode{
		ID:       "target-1",
		NodeType: "target",
		Value:    "test.acme.com",
	}

	vuln1Props, _ := json.Marshal(map[string]interface{}{
		"title":       "OAuth redirect_uri misconfig",
		"description": "OAuth misconfiguration",
	})
	vuln1Node := storage.AssetNode{
		ID:         "vuln-oauth",
		NodeType:   "vulnerability",
		Value:      "oauth-misconfig",
		Properties: vuln1Props,
	}

	vuln2Props, _ := json.Marshal(map[string]interface{}{
		"title":       "Open Redirect in login",
		"description": "Open redirect parameter",
	})
	vuln2Node := storage.AssetNode{
		ID:         "vuln-openredirect",
		NodeType:   "vulnerability",
		Value:      "open-redirect",
		Properties: vuln2Props,
	}

	nodes := []storage.AssetNode{targetNode, vuln1Node, vuln2Node}

	edges := []storage.AssetEdge{
		{
			SourceID: "target-1",
			TargetID: "vuln-oauth",
			Relation: "is_vulnerable_to",
		},
		{
			SourceID: "target-1",
			TargetID: "vuln-openredirect",
			Relation: "is_vulnerable_to",
		},
	}

	chains := FindVulnerabilityChains(nodes, edges)

	if len(chains) != 1 {
		t.Fatalf("expected 1 chain, got %d", len(chains))
	}

	c := chains[0]
	if c.Target != "test.acme.com" {
		t.Errorf("expected target test.acme.com, got %s", c.Target)
	}
	if c.CombinedCVSS != 9.8 {
		t.Errorf("expected combined CVSS 9.8, got %f", c.CombinedCVSS)
	}
	if c.ChainType != "Account Takeover via OAuth hijacking" {
		t.Errorf("unexpected chain type: %s", c.ChainType)
	}
}
