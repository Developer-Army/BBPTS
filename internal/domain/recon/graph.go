package recon

import (
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"
)

// GraphNode represents an entity in the attack surface.
type GraphNode struct {
	ID              string
	Type            string // e.g., "Domain", "Subdomain", "JS_File", "GraphQL_Endpoint", "IP"
	Properties      map[string]string
	Provenance      string    // source tool/track
	Confidence      float64   // confidence value (0.0 to 1.0)
	FirstSeen       time.Time
	LastSeen        time.Time
	OwnerID         string
	OwnerConfidence float64
	BlastRadius     float64
}

// GraphEdge represents a relationship between two entities.
type GraphEdge struct {
	SourceID   string
	TargetID   string
	Relation   string  // e.g., "RESOLVES_TO", "LOADS", "EXPOSES", "REFERENCES"
	Weight     int     // Difficulty weight (higher = harder/costlier for attacker)
	Confidence float64 // edge confidence
	Provenance string
	LastSeen   time.Time
}

// MemoryGraph is an in-memory graph to cluster relationships.
type MemoryGraph struct {
	nodes map[string]*GraphNode
	edges []GraphEdge
	mu    sync.RWMutex
}

func NewMemoryGraph() *MemoryGraph {
	return &MemoryGraph{
		nodes: make(map[string]*GraphNode),
		edges: make([]GraphEdge, 0),
	}
}

// AddNode adds an entity to the graph.
func (g *MemoryGraph) AddNode(node *GraphNode) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if node.ID == "" {
		node.ID = fmt.Sprintf("%s:%s", node.Type, node.Properties["Value"])
	}
	if node.FirstSeen.IsZero() {
		node.FirstSeen = time.Now()
	}
	if node.LastSeen.IsZero() {
		node.LastSeen = time.Now()
	}
	if node.Confidence <= 0 {
		node.Confidence = 1.0
	}

	if existing, exists := g.nodes[node.ID]; exists {
		// Update properties, confidence and last seen time
		existing.LastSeen = node.LastSeen
		if node.Confidence > 0 {
			existing.Confidence = node.Confidence
		}
		if node.OwnerID != "" {
			existing.OwnerID = node.OwnerID
			existing.OwnerConfidence = node.OwnerConfidence
		}
		if node.BlastRadius > 0 {
			existing.BlastRadius = node.BlastRadius
		}
		for k, v := range node.Properties {
			if existing.Properties == nil {
				existing.Properties = make(map[string]string)
			}
			existing.Properties[k] = v
		}
	} else {
		g.nodes[node.ID] = node
		slog.Debug("Graph: Added node", "id", node.ID, "type", node.Type)
	}
}

// AddEdge creates a relationship pivot between entities.
func (g *MemoryGraph) AddEdge(sourceID, targetID, relation string, weight int) {
	g.AddEdgeAdvanced(sourceID, targetID, relation, weight, 1.0, "system")
}

// AddEdgeAdvanced creates a relationship with confidence and provenance metadata.
func (g *MemoryGraph) AddEdgeAdvanced(sourceID, targetID, relation string, weight int, confidence float64, provenance string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	// Ensure both nodes exist before linking (basic safety)
	if _, ok := g.nodes[sourceID]; !ok {
		slog.Debug("Graph: Attempted to link from unknown source", "source", sourceID)
		return
	}
	if _, ok := g.nodes[targetID]; !ok {
		slog.Debug("Graph: Attempted to link to unknown target", "target", targetID)
		return
	}

	edge := GraphEdge{
		SourceID:   sourceID,
		TargetID:   targetID,
		Relation:   relation,
		Weight:     weight,
		Confidence: confidence,
		Provenance: provenance,
		LastSeen:   time.Now(),
	}
	g.edges = append(g.edges, edge)
}

// FindPivots returns all connected nodes to a given starting ID.
func (g *MemoryGraph) FindPivots(startID string) []*GraphNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var results []*GraphNode
	seen := make(map[string]bool)

	for _, edge := range g.edges {
		if edge.SourceID == startID {
			if !seen[edge.TargetID] {
				seen[edge.TargetID] = true
				if targetNode, ok := g.nodes[edge.TargetID]; ok {
					results = append(results, targetNode)
				}
			}
		}
	}
	return results
}

// PropagateRisk calculates risk scores of nodes by propagating risk dynamically across adjacent edges.
func (g *MemoryGraph) PropagateRisk(initialRisk map[string]float64) map[string]float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	propagated := make(map[string]float64)
	for k, v := range initialRisk {
		propagated[k] = v
	}

	// Two-pass propagation to handle transitive edges
	for pass := 0; pass < 2; pass++ {
		for _, edge := range g.edges {
			targetRisk := propagated[edge.TargetID]
			if targetRisk > 0 {
				edgeFactor := 0.2
				if edge.Weight > 0 {
					edgeFactor = float64(edge.Weight) / 100.0
				}
				// Factor in edge confidence
				edgeConf := edge.Confidence
				if edgeConf <= 0 {
					edgeConf = 1.0
				}

				targetConf := 1.0
				if targetNode, ok := g.nodes[edge.TargetID]; ok {
					if targetNode.Confidence > 0 {
						targetConf = targetNode.Confidence
					}
				}

				propRisk := targetRisk * edgeFactor * edgeConf * targetConf
				if propRisk > propagated[edge.SourceID] {
					propagated[edge.SourceID] = propRisk
				}
			}
		}
	}

	return propagated
}

// ApplyTimeDecay applies confidence decay based on last seen times.
// confidence decays exponentially: C = C_orig * e^(-lambda * daysOld)
func (g *MemoryGraph) ApplyTimeDecay(now time.Time, halfLifeDays float64) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if halfLifeDays <= 0 {
		halfLifeDays = 30.0
	}
	lambda := math.Log(2) / halfLifeDays

	// Decay node confidence
	for _, node := range g.nodes {
		daysOld := now.Sub(node.LastSeen).Hours() / 24.0
		if daysOld > 0 {
			decay := math.Exp(-lambda * daysOld)
			node.Confidence *= decay
		}
	}

	// Decay edge confidence
	for i := range g.edges {
		daysOld := now.Sub(g.edges[i].LastSeen).Hours() / 24.0
		if daysOld > 0 {
			decay := math.Exp(-lambda * daysOld)
			g.edges[i].Confidence *= decay
		}
	}
}

// PropagateBlastRadius calculates the cumulative downstream impact of compromising a node.
func (g *MemoryGraph) PropagateBlastRadius(startID string) float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	startNode, ok := g.nodes[startID]
	if !ok {
		return 0.0
	}

	visited := make(map[string]bool)
	queue := []string{startID}
	visited[startID] = true

	totalBlastRadius := startNode.BlastRadius
	if totalBlastRadius <= 0 {
		totalBlastRadius = 10.0 // default node impact
	}

	// Adjacency mapping
	adj := make(map[string][]string)
	for _, edge := range g.edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edge.TargetID)
	}

	depth := 0
	maxDepth := 4

	for len(queue) > 0 && depth < maxDepth {
		size := len(queue)
		for i := 0; i < size; i++ {
			curr := queue[0]
			queue = queue[1:]

			for _, neighbor := range adj[curr] {
				if !visited[neighbor] {
					visited[neighbor] = true
					node, exists := g.nodes[neighbor]
					nodeImpact := 5.0
					if exists && node.BlastRadius > 0 {
						nodeImpact = node.BlastRadius
					}
					// Damped propagation based on distance
					totalBlastRadius += nodeImpact * math.Pow(0.5, float64(depth+1))
					queue = append(queue, neighbor)
				}
			}
		}
		depth++
	}

	return totalBlastRadius
}

// CalculatePathCost computes the attacker transition cost of a given path.
// The cost is calculated by summing the edge weights (difficulty) divided by edge/node confidence.
func (g *MemoryGraph) CalculatePathCost(path []string) float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if len(path) < 2 {
		return 0.0
	}

	totalCost := 0.0
	edgeMap := make(map[string][]GraphEdge)
	for _, edge := range g.edges {
		key := fmt.Sprintf("%s->%s", edge.SourceID, edge.TargetID)
		edgeMap[key] = append(edgeMap[key], edge)
	}

	for i := 0; i < len(path)-1; i++ {
		src := path[i]
		tgt := path[i+1]
		key := fmt.Sprintf("%s->%s", src, tgt)

		edges, exists := edgeMap[key]
		if !exists || len(edges) == 0 {
			return math.MaxFloat64 // Disconnected path
		}

		// Find the lowest cost edge between these two nodes
		minEdgeCost := math.MaxFloat64
		for _, edge := range edges {
			weight := float64(edge.Weight)
			if weight <= 0 {
				weight = 10.0 // default difficulty weight
			}
			conf := edge.Confidence
			if conf <= 0 {
				conf = 0.5
			}
			edgeCost := weight / conf
			if edgeCost < minEdgeCost {
				minEdgeCost = edgeCost
			}
		}
		totalCost += minEdgeCost
	}

	return totalCost
}

// GetCheapestAttackPath finds the attack path from sourceID to targetID with the lowest total path cost.
func (g *MemoryGraph) GetCheapestAttackPath(sourceID, targetID string) ([]string, float64) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	if _, ok := g.nodes[sourceID]; !ok {
		return nil, -1.0
	}
	if _, ok := g.nodes[targetID]; !ok {
		return nil, -1.0
	}

	// Dijkstra implementation for cheapest path
	dist := make(map[string]float64)
	prev := make(map[string]string)
	for id := range g.nodes {
		dist[id] = math.MaxFloat64
	}
	dist[sourceID] = 0.0

	// Adjacency mapping
	adj := make(map[string][]GraphEdge)
	for _, edge := range g.edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edge)
	}

	visited := make(map[string]bool)

	for {
		// Find node with minimum distance
		var u string
		minDist := math.MaxFloat64
		for id := range g.nodes {
			if !visited[id] && dist[id] < minDist {
				minDist = dist[id]
				u = id
			}
		}

		if u == "" || u == targetID || minDist == math.MaxFloat64 {
			break
		}

		visited[u] = true

		for _, edge := range adj[u] {
			v := edge.TargetID
			if visited[v] {
				continue
			}
			weight := float64(edge.Weight)
			if weight <= 0 {
				weight = 10.0
			}
			conf := edge.Confidence
			if conf <= 0 {
				conf = 0.5
			}
			cost := weight / conf

			alt := dist[u] + cost
			if alt < dist[v] {
				dist[v] = alt
				prev[v] = u
			}
		}
	}

	if dist[targetID] == math.MaxFloat64 {
		return nil, -1.0
	}

	// Reconstruct path
	var path []string
	curr := targetID
	for curr != "" {
		path = append([]string{curr}, path...)
		curr = prev[curr]
	}

	return path, dist[targetID]
}
