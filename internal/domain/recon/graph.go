package recon

import (
	"fmt"
	"log/slog"
	"sync"
)

// GraphNode represents an entity in the attack surface.
type GraphNode struct {
	ID         string
	Type       string // e.g., "Domain", "Subdomain", "JS_File", "GraphQL_Endpoint", "IP"
	Properties map[string]string
}

// GraphEdge represents a relationship between two entities.
type GraphEdge struct {
	SourceID string
	TargetID string
	Relation string // e.g., "RESOLVES_TO", "LOADS", "EXPOSES", "REFERENCES"
	Weight   int
}

// MemoryGraph is an in-memory graph to cluster relationships.
// It allows discovering pivots: Subdomain -> JS File -> Secret Token.
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

	if _, exists := g.nodes[node.ID]; !exists {
		g.nodes[node.ID] = node
		slog.Debug("Graph: Added node", "id", node.ID, "type", node.Type)
	}
}

// AddEdge creates a relationship pivot between entities.
func (g *MemoryGraph) AddEdge(sourceID, targetID, relation string, weight int) {
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
		SourceID: sourceID,
		TargetID: targetID,
		Relation: relation,
		Weight:   weight,
	}
	g.edges = append(g.edges, edge)
}

// FindPivots returns all connected nodes to a given starting ID.
func (g *MemoryGraph) FindPivots(startID string) []*GraphNode {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var results []*GraphNode
	seen := make(map[string]bool)

	// Basic 1-degree pivot search
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
