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
func (s *Storage) GetAllAssetNodes(limit, offset int) ([]AssetNode, error) {
	query := "SELECT id, node_type, value, properties, scope_id, first_seen, last_seen, source, confidence FROM asset_nodes"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else if offset > 0 {
		query += fmt.Sprintf(" LIMIT -1 OFFSET %d", offset)
	}
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
func (s *Storage) GetAllAssetEdges(limit, offset int) ([]AssetEdge, error) {
	query := "SELECT source_id, target_id, relation, first_seen, last_seen, confidence, observed_at, evidence_id FROM asset_edges"
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", limit)
		if offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", offset)
		}
	} else if offset > 0 {
		query += fmt.Sprintf(" LIMIT -1 OFFSET %d", offset)
	}
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

// LinkAssetChain links subdomain -> service -> technology -> owner -> repo -> cloud asset -> finding
func (s *Storage) LinkAssetChain(subdomain, service, technology, ownerEmail, repo, cloudAsset, findingTitle, criticality, environment string) error {
	meta := map[string]string{
		"criticality": criticality,
		"environment": environment,
	}

	subdomainID, err := s.SaveNode("subdomain", subdomain, meta, "", "system", 1.0)
	if err != nil {
		return err
	}
	serviceID, err := s.SaveNode("service", service, meta, "", "system", 1.0)
	if err != nil {
		return err
	}
	techID, err := s.SaveNode("technology", technology, nil, "", "system", 1.0)
	if err != nil {
		return err
	}
	ownerID, err := s.SaveNode("owner", ownerEmail, nil, "", "system", 1.0)
	if err != nil {
		return err
	}
	repoID, err := s.SaveNode("repo", repo, nil, "", "system", 1.0)
	if err != nil {
		return err
	}
	cloudAssetID, err := s.SaveNode("cloud_asset", cloudAsset, meta, "", "system", 1.0)
	if err != nil {
		return err
	}
	findingID, err := s.SaveNode("finding", findingTitle, nil, "", "system", 1.0)
	if err != nil {
		return err
	}

	// Save edges representing the provenance chain
	_ = s.SaveEdge(subdomainID, serviceID, "exposes", 1.0, "system")
	_ = s.SaveEdge(serviceID, techID, "uses_tech", 1.0, "system")
	_ = s.SaveEdge(serviceID, ownerID, "owned_by", 1.0, "system")
	_ = s.SaveEdge(serviceID, repoID, "deployed_from", 1.0, "system")
	_ = s.SaveEdge(repoID, cloudAssetID, "hosted_on", 1.0, "system")
	_ = s.SaveEdge(cloudAssetID, findingID, "has_finding", 1.0, "system")

	return nil
}

// PropagateRisk calculates threat scores for all nodes by propagating risk from findings.
func (s *Storage) PropagateRisk() (map[string]float64, error) {
	nodes, err := s.GetAllAssetNodes(0, 0)
	if err != nil {
		return nil, err
	}
	edges, err := s.GetAllAssetEdges(0, 0)
	if err != nil {
		return nil, err
	}

	scores := make(map[string]float64)
	queue := make([]string, 0)

	// Initialize finding nodes with their base threat score
	for _, node := range nodes {
		if node.NodeType == "finding" {
			// Base score of 90.0 for finding risk
			scores[node.ID] = 90.0
			queue = append(queue, node.ID)
		} else {
			scores[node.ID] = 0.0
		}
	}

	// Adjacency list representation (incoming & outgoing edges)
	adj := make(map[string][]AssetEdge)
	for _, edge := range edges {
		adj[edge.SourceID] = append(adj[edge.SourceID], edge)
		adj[edge.TargetID] = append(adj[edge.TargetID], edge)
	}

	// Propagate risk scores using BFS with a max depth/damping factor
	visited := make(map[string]int)
	for len(queue) > 0 {
		currID := queue[0]
		queue = queue[1:]

		currScore := scores[currID]
		depth := visited[currID]
		if depth >= 5 {
			continue
		}

		for _, edge := range adj[currID] {
			neighborID := edge.SourceID
			if neighborID == currID {
				neighborID = edge.TargetID
			}

			// Time decay factor based on how long since last observed (default 30 day half-life)
			lastSeenTime, parseErr := time.Parse(time.RFC3339, edge.LastSeen)
			decayFactor := 1.0
			if parseErr == nil {
				daysOld := time.Since(lastSeenTime).Hours() / 24.0
				if daysOld > 0 {
					decayFactor = 1.0 / (1.0 + daysOld/30.0)
				}
			}

			// Damping factor decreases threat score over path length
			propagated := currScore * edge.Confidence * decayFactor * 0.8
			if propagated > scores[neighborID] {
				scores[neighborID] = propagated
				visited[neighborID] = depth + 1
				queue = append(queue, neighborID)
			}
		}
	}

	return scores, nil
}

