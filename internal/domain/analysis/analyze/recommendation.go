package analyze

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/risk"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

type InvestigationTarget struct {
	AssetID            string   `json:"asset_id"`
	ExposureScore      float64  `json:"exposure_score"`
	AttackabilityScore float64  `json:"attackability_score"`
	BusinessScore      float64  `json:"business_score"`
	ConfidenceScore    float64  `json:"confidence_score"`
	PathRiskScore      float64  `json:"path_risk_score"`
	FinalScore         float64  `json:"final_score"`
	Why                []string `json:"why"`
}

type AttackPath struct {
	Path  []string `json:"path"`
	Score float64  `json:"score"`
}

func getBaseNodeScore(node storage.AssetNode) float64 {
	lowerValue := strings.ToLower(node.Value)
	lowerType := strings.ToLower(node.NodeType)

	if lowerType == "vulnerability" {
		var props map[string]interface{}
		if err := json.Unmarshal(node.Properties, &props); err == nil {
			if sev, ok := props["severity"]; ok {
				switch strings.ToLower(fmt.Sprintf("%v", sev)) {
				case "critical":
					return 100
				case "high":
					return 80
				case "medium":
					return 50
				case "low":
					return 20
				}
			}
		}
		return 50
	}

	if strings.Contains(lowerValue, "k8s") || strings.Contains(lowerValue, "kubernetes") {
		return 100
	}
	if strings.Contains(lowerValue, "okta") || strings.Contains(lowerValue, "saml") || strings.Contains(lowerValue, "keycloak") {
		return 95
	}
	if strings.Contains(lowerValue, "vpn") || strings.Contains(lowerValue, "gateway") {
		return 95
	}
	if strings.Contains(lowerValue, "jenkins") || strings.Contains(lowerValue, "gitlab") || strings.Contains(lowerValue, "github") || strings.Contains(lowerValue, "ci-cd") {
		return 90
	}
	if strings.Contains(lowerValue, "admin") || strings.Contains(lowerValue, "dashboard") || strings.Contains(lowerValue, "management") {
		return 90
	}
	if strings.Contains(lowerValue, "grafana") || strings.Contains(lowerValue, "prometheus") || strings.Contains(lowerValue, "kibana") {
		return 80
	}
	if strings.Contains(lowerValue, "checkout") || strings.Contains(lowerValue, "payment") || strings.Contains(lowerValue, "stripe") || strings.Contains(lowerValue, "pay") {
		return 100
	}
	if strings.Contains(lowerValue, "api") || strings.Contains(lowerValue, "graphql") {
		return 60
	}
	if strings.Contains(lowerValue, "s3") || strings.Contains(lowerValue, "blob") || strings.Contains(lowerValue, "storage") {
		return 85
	}
	return 20
}

func calculatePathScore(path []string, nodeMap map[string]storage.AssetNode) float64 {
	if len(path) == 0 {
		return 0
	}
	var maxNodeScore float64 = 0
	for _, id := range path {
		node, exists := nodeMap[id]
		if !exists {
			continue
		}
		score := getBaseNodeScore(node)
		if score > maxNodeScore {
			maxNodeScore = score
		}
	}
	finalScore := maxNodeScore
	if len(path) > 1 {
		finalScore += float64(len(path)-1) * 2.0
	}
	if finalScore > 100 {
		finalScore = 100
	}
	return finalScore
}

func GetAttackPaths(nodes []storage.AssetNode, edges []storage.AssetEdge) []AttackPath {
	adj := make(map[string][]string)
	for _, edge := range edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edge.TargetID)
	}

	nodeMap := make(map[string]storage.AssetNode)
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}

	var paths []AttackPath
	var currentPath []string
	visited := make(map[string]bool)

	var dfs func(u string, depth int)
	dfs = func(u string, depth int) {
		if depth > 5 {
			return
		}
		visited[u] = true
		currentPath = append(currentPath, u)

		node, exists := nodeMap[u]
		if exists && (node.NodeType == "vulnerability" || node.NodeType == "endpoint") {
			pathCopy := make([]string, len(currentPath))
			copy(pathCopy, currentPath)
			paths = append(paths, AttackPath{
				Path:  pathCopy,
				Score: calculatePathScore(pathCopy, nodeMap),
			})
		}

		for _, v := range adj[u] {
			if !visited[v] {
				dfs(v, depth+1)
			}
		}

		currentPath = currentPath[:len(currentPath)-1]
		visited[u] = false
	}

	for _, node := range nodes {
		if node.NodeType == "target" || node.NodeType == "domain" || node.NodeType == "subdomain" {
			dfs(node.ID, 1)
		}
	}

	return paths
}

func RankAttackPaths(paths []AttackPath) []AttackPath {
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Score != paths[j].Score {
			return paths[i].Score > paths[j].Score
		}
		return len(paths[i].Path) < len(paths[j].Path)
	})
	return paths
}

func CalculateBlastRadius(nodeID string, edges []storage.AssetEdge, nodes []storage.AssetNode) ([]string, error) {
	adj := make(map[string][]string)
	for _, edge := range edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edge.TargetID)
	}

	nodeMap := make(map[string]storage.AssetNode)
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}

	visited := make(map[string]bool)
	var queue []string
	queue = append(queue, nodeID)
	visited[nodeID] = true

	var reachable []string
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr != nodeID {
			node, exists := nodeMap[curr]
			if exists {
				reachable = append(reachable, node.Value)
			} else {
				reachable = append(reachable, curr)
			}
		}

		for _, next := range adj[curr] {
			if !visited[next] {
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}

	return reachable, nil
}

func calculateExposure(node storage.AssetNode) float64 {
	lowerVal := strings.ToLower(node.Value)
	if strings.Contains(lowerVal, "internal") || strings.Contains(lowerVal, "local") || strings.Contains(lowerVal, "private") || strings.Contains(lowerVal, "dev") || strings.Contains(lowerVal, "staging") || strings.Contains(lowerVal, "test") {
		return 40.0
	}
	return 100.0
}

func calculateAttackability(nodeID string, incoming, outgoing map[string][]string, nodeMap map[string]storage.AssetNode) (float64, []string) {
	var score float64 = 30.0
	var why []string

	for _, targetID := range outgoing[nodeID] {
		targetNode, exists := nodeMap[targetID]
		if !exists {
			continue
		}

		if targetNode.NodeType == "vulnerability" {
			var props map[string]interface{}
			if err := json.Unmarshal(targetNode.Properties, &props); err == nil {
				if sev, ok := props["severity"]; ok {
					s := strings.ToLower(fmt.Sprintf("%v", sev))
					if s == "critical" {
						score += 40
						why = append(why, "✓ Critical CVE")
					} else if s == "high" {
						score += 30
						why = append(why, "✓ High Severity CVE")
					} else {
						score += 15
						why = append(why, "✓ Vulnerability Found")
					}
				}
			}
		}

		if targetNode.NodeType == "endpoint" {
			score += 10
			lowerVal := strings.ToLower(targetNode.Value)
			if strings.Contains(lowerVal, "login") || strings.Contains(lowerVal, "auth") || strings.Contains(lowerVal, "admin") {
				score += 20
				why = append(why, "✓ Authentication Surface")
			}
		}

		if targetNode.NodeType == "service" {
			var props map[string]interface{}
			if err := json.Unmarshal(targetNode.Properties, &props); err == nil {
				if waf, ok := props["waf"]; ok {
					if strings.ToLower(fmt.Sprintf("%v", waf)) == "none" || fmt.Sprintf("%v", waf) == "" {
						score += 15
						why = append(why, "✓ No WAF")
					}
				}
			}
		}
	}

	if score > 100 {
		score = 100
	}
	return score, why
}

func calculateNodePathRisk(nodeID string, incoming, outgoing map[string][]string, nodeMap map[string]storage.AssetNode) float64 {
	visited := make(map[string]bool)
	var maxRisk float64 = 0

	var traverse func(curr string, depth int)
	traverse = func(curr string, depth int) {
		if depth > 3 {
			return
		}
		visited[curr] = true

		node, exists := nodeMap[curr]
		if exists && node.NodeType == "vulnerability" {
			vScore := getBaseNodeScore(node)
			if vScore > maxRisk {
				maxRisk = vScore
			}
		}

		for _, next := range outgoing[curr] {
			if !visited[next] {
				traverse(next, depth+1)
			}
		}
		visited[curr] = false
	}

	traverse(nodeID, 1)
	return maxRisk
}

func PropagateRisk(nodes []storage.AssetNode, edges []storage.AssetEdge) map[string]float64 {
	riskMap := make(map[string]float64)
	for _, node := range nodes {
		riskMap[node.ID] = getBaseNodeScore(node)
	}

	for iter := 0; iter < 3; iter++ {
		nextRisk := make(map[string]float64)
		for k, v := range riskMap {
			nextRisk[k] = v
		}

		for _, edge := range edges {
			sourceRisk := riskMap[edge.SourceID]
			inherited := sourceRisk * 0.7
			if inherited > nextRisk[edge.TargetID] {
				nextRisk[edge.TargetID] = inherited
			}
		}
		riskMap = nextRisk
	}
	return riskMap
}

func RecommendTargets(nodes []storage.AssetNode, edges []storage.AssetEdge) []InvestigationTarget {
	nodeMap := make(map[string]storage.AssetNode)
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}

	incoming := make(map[string][]string)
	outgoing := make(map[string][]string)
	for _, edge := range edges {
		outgoing[edge.SourceID] = append(outgoing[edge.SourceID], edge.TargetID)
		incoming[edge.TargetID] = append(incoming[edge.TargetID], edge.SourceID)
	}

	propagatedRisk := PropagateRisk(nodes, edges)
	var targets []InvestigationTarget

	for _, node := range nodes {
		if node.NodeType != "target" && node.NodeType != "domain" && node.NodeType != "subdomain" {
			continue
		}

		exposure := calculateExposure(node)
		attackability, whyAttack := calculateAttackability(node.ID, incoming, outgoing, nodeMap)
		business := getBaseNodeScore(node)
		confidence := node.Confidence * 100.0
		if confidence == 0 {
			confidence = 80.0
		}

		pathRisk := calculateNodePathRisk(node.ID, incoming, outgoing, nodeMap)

		why := []string{}
		if exposure >= 80 {
			why = append(why, "✓ Internet Facing")
		}
		if len(whyAttack) > 0 {
			why = append(why, whyAttack...)
		}
		
		propagated := propagatedRisk[node.ID]
		if propagated > business {
			why = append(why, fmt.Sprintf("✓ Propagated Dependency Risk: %.0f", propagated))
			business = propagated
		}

		if business >= 80 && propagated <= getBaseNodeScore(node) {
			why = append(why, fmt.Sprintf("✓ High Asset Class: %.0f", business))
		}

		finalScore := float64(risk.CalculateRisk(risk.RiskFactors{
			Exposure:       int(exposure),
			Exploitability: int(attackability),
			BusinessImpact: int(business),
			Confidence:     int(confidence),
			AttackPath:     int(pathRisk),
		}))
		if finalScore > 100 {
			finalScore = 100
		}

		targets = append(targets, InvestigationTarget{
			AssetID:            node.Value,
			ExposureScore:      exposure,
			AttackabilityScore: attackability,
			BusinessScore:      business,
			ConfidenceScore:    confidence,
			PathRiskScore:      pathRisk,
			FinalScore:         finalScore,
			Why:                why,
		})
	}

	sort.Slice(targets, func(i, j int) bool {
		return targets[i].FinalScore > targets[j].FinalScore
	})

	if len(targets) > 10 {
		return targets[:10]
	}
	return targets
}
