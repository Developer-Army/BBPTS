package storage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// AssetNode represents a node in the reconnaissance asset graph.
type AssetNode struct {
	ID         string            `json:"id"`
	NodeType   string            `json:"node_type"`
	Value      string            `json:"value"`
	Properties map[string]string `json:"properties"`
}

// AssetEdge represents a directed relationship between two asset nodes.
type AssetEdge struct {
	SourceID  string `json:"source_id"`
	TargetID  string `json:"target_id"`
	Relation  string `json:"relation"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// GenerateNodeID creates a deterministic ID for a node based on its type and value.
func GenerateNodeID(nodeType, value string) string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s:%s", nodeType, value)))
	return fmt.Sprintf("%x", hash)
}

// SaveNode inserts or updates an asset node in the graph.
func (s *Storage) SaveNode(nodeType, value string, properties map[string]string) (string, error) {
	id := GenerateNodeID(nodeType, value)
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		return "", err
	}

	query := `
		INSERT INTO asset_nodes (id, node_type, value, properties, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			properties = excluded.properties
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO asset_nodes (id, node_type, value, properties, created_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT(id) DO UPDATE SET
				properties = EXCLUDED.properties
		`
	}

	_, err = s.db.Exec(query, id, nodeType, value, string(propsJSON), time.Now().UTC())
	return id, err
}

// SaveEdge inserts or updates a relationship edge between two nodes.
func (s *Storage) SaveEdge(sourceID, targetID, relation string) error {
	query := `
		INSERT INTO asset_edges (source_id, target_id, relation, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(source_id, target_id, relation) DO UPDATE SET
			last_seen = excluded.last_seen
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO asset_edges (source_id, target_id, relation, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT(source_id, target_id, relation) DO UPDATE SET
				last_seen = EXCLUDED.last_seen
		`
	}

	now := time.Now().UTC()
	_, err := s.db.Exec(query, sourceID, targetID, relation, now, now)
	return err
}

// GetGraphPaths recursively queries the graph to discover attack paths up to a specified depth.
func (s *Storage) GetGraphPaths(rootID string, maxDepth int) ([]AssetEdge, error) {
	// Recursive queries (CTEs) are supported by both SQLite and PostgreSQL.
	query := `
		WITH RECURSIVE paths(source_id, target_id, relation, depth) AS (
			SELECT source_id, target_id, relation, 1
			FROM asset_edges
			WHERE source_id = ?
			UNION
			SELECT e.source_id, e.target_id, e.relation, p.depth + 1
			FROM asset_edges e
			JOIN paths p ON e.source_id = p.target_id
			WHERE p.depth < ?
		)
		SELECT source_id, target_id, relation FROM paths
	`
	if s.dbType == "postgres" {
		query = `
			WITH RECURSIVE paths(source_id, target_id, relation, depth) AS (
				SELECT source_id, target_id, relation, 1
				FROM asset_edges
				WHERE source_id = $1
				UNION
				SELECT e.source_id, e.target_id, e.relation, p.depth + 1
				FROM asset_edges e
				JOIN paths p ON e.source_id = p.target_id
				WHERE p.depth < $2
			)
			SELECT source_id, target_id, relation FROM paths
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
		if err := rows.Scan(&edge.SourceID, &edge.TargetID, &edge.Relation); err != nil {
			return nil, err
		}
		edges = append(edges, edge)
	}
	return edges, nil
}
