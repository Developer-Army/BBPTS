package storage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// AssetNode represents a node in the reconnaissance asset graph.
type AssetNode struct {
	ID         string          `json:"id"`
	NodeType   string          `json:"node_type"`
	Value      string          `json:"value"`
	Properties json.RawMessage `json:"properties"`
	ScopeID    string          `json:"scope_id"`
	FirstSeen  string          `json:"first_seen"`
	LastSeen   string          `json:"last_seen"`
	Source     string          `json:"source"`
	Confidence float64         `json:"confidence"`
}

// AssetEdge represents a directed relationship between two asset nodes.
type AssetEdge struct {
	SourceID   string    `json:"source_id"`
	TargetID   string    `json:"target_id"`
	Relation   string    `json:"relation"`
	FirstSeen  string    `json:"first_seen"`
	LastSeen   string    `json:"last_seen"`
	Confidence float64   `json:"confidence"`
	ObservedAt string    `json:"observed_at"`
	EvidenceID string    `json:"evidence_id"`
}

// GenerateNodeID creates a deterministic ID for a node based on its type, value and scopeID.
func GenerateNodeID(nodeType, value, scopeID string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", strings.ToLower(nodeType), value, scopeID)))
	return fmt.Sprintf("%x", hash)
}

// SaveNode inserts or updates an asset node in the graph.
func (s *Storage) SaveNode(nodeType, value string, properties interface{}, scopeID string, source string, confidence float64) (string, error) {
	nodeType = strings.ToLower(nodeType)
	id := GenerateNodeID(nodeType, value, scopeID)

	var propsJSON []byte
	var err error
	if properties != nil {
		switch p := properties.(type) {
		case json.RawMessage:
			propsJSON = p
		case []byte:
			propsJSON = p
		case string:
			propsJSON = []byte(p)
		default:
			propsJSON, err = json.Marshal(properties)
			if err != nil {
				return "", err
			}
		}
	} else {
		propsJSON = []byte("{}")
	}

	now := time.Now().UTC()
	query := `
		INSERT INTO asset_nodes (id, node_type, value, properties, scope_id, first_seen, last_seen, source, confidence, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			properties = excluded.properties,
			last_seen = excluded.last_seen,
			confidence = excluded.confidence
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO asset_nodes (id, node_type, value, properties, scope_id, first_seen, last_seen, source, confidence, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			ON CONFLICT(id) DO UPDATE SET
				properties = EXCLUDED.properties,
				last_seen = EXCLUDED.last_seen,
				confidence = EXCLUDED.confidence
		`
	}

	_, err = s.db.Exec(query, id, nodeType, value, string(propsJSON), scopeID, now, now, source, confidence, now)
	return id, err
}

// SaveEdge inserts or updates a relationship edge between two nodes.
func (s *Storage) SaveEdge(sourceID, targetID, relation string, confidence float64, evidenceID string) error {
	relation = strings.ToLower(relation)
	query := `
		INSERT INTO asset_edges (source_id, target_id, relation, first_seen, last_seen, confidence, observed_at, evidence_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(source_id, target_id, relation) DO UPDATE SET
			last_seen = excluded.last_seen,
			confidence = excluded.confidence,
			observed_at = excluded.observed_at,
			evidence_id = excluded.evidence_id
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO asset_edges (source_id, target_id, relation, first_seen, last_seen, confidence, observed_at, evidence_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT(source_id, target_id, relation) DO UPDATE SET
				last_seen = EXCLUDED.last_seen,
				confidence = EXCLUDED.confidence,
				observed_at = EXCLUDED.observed_at,
				evidence_id = EXCLUDED.evidence_id
		`
	}

	now := time.Now().UTC()
	_, err := s.db.Exec(query, sourceID, targetID, relation, now, now, confidence, now, evidenceID)
	return err
}

// GetGraphPaths recursively queries the graph to discover attack paths up to a specified depth.
func (s *Storage) GetGraphPaths(rootID string, maxDepth int) ([]AssetEdge, error) {
	if maxDepth > 10 {
		maxDepth = 10
	}
	if maxDepth <= 0 {
		maxDepth = 3
	}
	query := `
		WITH RECURSIVE paths(source_id, target_id, relation, depth, visited) AS (
			SELECT source_id, target_id, relation, 1, ',' || source_id || ',' || target_id || ','
			FROM asset_edges
			WHERE source_id = ?
			UNION
			SELECT e.source_id, e.target_id, e.relation, p.depth + 1, p.visited || e.target_id || ','
			FROM asset_edges e
			JOIN paths p ON e.source_id = p.target_id
			WHERE p.depth < ? AND INSTR(p.visited, ',' || e.target_id || ',') = 0
		)
		SELECT p.source_id, p.target_id, p.relation, e.first_seen, e.last_seen, e.confidence, e.observed_at, e.evidence_id
		FROM paths p
		JOIN asset_edges e ON p.source_id = e.source_id AND p.target_id = e.target_id AND p.relation = e.relation
	`
	if s.dbType == "postgres" {
		query = `
			WITH RECURSIVE paths(source_id, target_id, relation, depth, visited) AS (
				SELECT source_id, target_id, relation, 1, ARRAY[source_id, target_id]
				FROM asset_edges
				WHERE source_id = $1
				UNION
				SELECT e.source_id, e.target_id, e.relation, p.depth + 1, p.visited || e.target_id
				FROM asset_edges e
				JOIN paths p ON e.source_id = p.target_id
				WHERE p.depth < $2 AND NOT (e.target_id = ANY(p.visited))
			)
			SELECT p.source_id, p.target_id, p.relation, e.first_seen, e.last_seen, e.confidence, e.observed_at, e.evidence_id
			FROM paths p
			JOIN asset_edges e ON p.source_id = e.source_id AND p.target_id = e.target_id AND p.relation = e.relation
		`
	}

	rows, err := s.db.Query(query, rootID, maxDepth)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []AssetEdge
	for rows.Next() {
		var edge AssetEdge
		if err := rows.Scan(&edge.SourceID, &edge.TargetID, &edge.Relation, &edge.FirstSeen, &edge.LastSeen, &edge.Confidence, &edge.ObservedAt, &edge.EvidenceID); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, nil
}

// GetUnownedAssets returns all target/domain/subdomain nodes without owners or teams assigned.
func (s *Storage) GetUnownedAssets() ([]AssetNode, error) {
	query := `
		SELECT id, node_type, value, properties, scope_id, first_seen, last_seen, source, confidence FROM asset_nodes
		WHERE node_type IN ('target', 'domain', 'subdomain')
		  AND id NOT IN (
		      SELECT source_id FROM asset_edges WHERE relation IN ('owned_by_owner', 'owned_by_team', 'owns')
		      UNION
		      SELECT target_id FROM asset_edges WHERE relation IN ('owned_by_owner', 'owned_by_team', 'owns')
		  )
	`
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []AssetNode
	for rows.Next() {
		var n AssetNode
		var propsJSON string
		if err := rows.Scan(&n.ID, &n.NodeType, &n.Value, &propsJSON, &n.ScopeID, &n.FirstSeen, &n.LastSeen, &n.Source, &n.Confidence); err != nil {
			return nil, err
		}
		n.Properties = json.RawMessage(propsJSON)
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// GetNodesByIDs retrieves multiple asset nodes by their deterministic IDs.
func (s *Storage) GetNodesByIDs(ids []string) ([]AssetNode, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]interface{}, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		if s.dbType == "postgres" {
			placeholders[i] = fmt.Sprintf("$%d", i+1)
		}
		args[i] = id
	}
	query := fmt.Sprintf("SELECT id, node_type, value, properties, scope_id, first_seen, last_seen, source, confidence FROM asset_nodes WHERE id IN (%s)", strings.Join(placeholders, ", "))
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []AssetNode
	for rows.Next() {
		var n AssetNode
		var propsJSON string
		if err := rows.Scan(&n.ID, &n.NodeType, &n.Value, &propsJSON, &n.ScopeID, &n.FirstSeen, &n.LastSeen, &n.Source, &n.Confidence); err != nil {
			return nil, err
		}
		n.Properties = json.RawMessage(propsJSON)
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// GetShortestAttackPath finds the shortest path of edges from sourceID to targetID.
func (s *Storage) GetShortestAttackPath(sourceID, targetID string, maxDepth int) ([]AssetEdge, error) {
	edges, err := s.GetGraphPaths(sourceID, maxDepth)
	if err != nil {
		return nil, err
	}

	adj := make(map[string][]AssetEdge)
	for _, edge := range edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edge)
	}

	type queueItem struct {
		node string
		path []AssetEdge
	}

	queue := []queueItem{{node: sourceID, path: []AssetEdge{}}}
	visited := map[string]bool{sourceID: true}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if curr.node == targetID {
			return curr.path, nil
		}

		for _, edge := range adj[curr.node] {
			if !visited[edge.TargetID] {
				visited[edge.TargetID] = true
				newPath := append([]AssetEdge{}, curr.path...)
				newPath = append(newPath, edge)
				queue = append(queue, queueItem{node: edge.TargetID, path: newPath})
			}
		}
	}

	return nil, fmt.Errorf("no path found between %s and %s within depth %d", sourceID, targetID, maxDepth)
}

// GetBlastRadius finds downstream assets/nodes affected by serviceID.
func (s *Storage) GetBlastRadius(serviceID string, maxDepth int) ([]AssetNode, error) {
	edges, err := s.GetGraphPaths(serviceID, maxDepth)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	var ids []string
	for _, edge := range edges {
		if !seen[edge.TargetID] {
			seen[edge.TargetID] = true
			ids = append(ids, edge.TargetID)
		}
	}
	return s.GetNodesByIDs(ids)
}

// GetTeamOverdueFindings groups overdue findings by responsible team.
func (s *Storage) GetTeamOverdueFindings() (map[string][]OverdueAssignment, error) {
	overdue, err := s.GetOverdueAssignments()
	if err != nil {
		return nil, err
	}

	result := make(map[string][]OverdueAssignment)
	for _, oa := range overdue {
		teamName := "Unassigned"
		if oa.TeamID != nil {
			team, err := s.GetTeam(*oa.TeamID)
			if err == nil && team != nil {
				teamName = team.Name
			}
		}
		result[teamName] = append(result[teamName], oa)
	}
	return result, nil
}

// GetAllAssetNodes retrieves all asset nodes.
func (s *Storage) GetAllAssetNodes() ([]AssetNode, error) {
	query := "SELECT id, node_type, value, properties, scope_id, first_seen, last_seen, source, confidence FROM asset_nodes LIMIT 5000"
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []AssetNode
	for rows.Next() {
		var n AssetNode
		var propsJSON string
		if err := rows.Scan(&n.ID, &n.NodeType, &n.Value, &propsJSON, &n.ScopeID, &n.FirstSeen, &n.LastSeen, &n.Source, &n.Confidence); err != nil {
			return nil, err
		}
		n.Properties = json.RawMessage(propsJSON)
		nodes = append(nodes, n)
	}
	return nodes, nil
}

// GetAllAssetEdges retrieves all asset edges.
func (s *Storage) GetAllAssetEdges() ([]AssetEdge, error) {
	query := "SELECT source_id, target_id, relation, first_seen, last_seen, confidence, observed_at, evidence_id FROM asset_edges LIMIT 5000"
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var edges []AssetEdge
	for rows.Next() {
		var edge AssetEdge
		if err := rows.Scan(&edge.SourceID, &edge.TargetID, &edge.Relation, &edge.FirstSeen, &edge.LastSeen, &edge.Confidence, &edge.ObservedAt, &edge.EvidenceID); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, nil
}

