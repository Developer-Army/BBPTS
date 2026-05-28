package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type Team struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

type Owner struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}

type AssetOwnership struct {
	ID        int64      `json:"id"`
	AssetID   string     `json:"asset_id"`
	OwnerID   *int64     `json:"owner_id,omitempty"`
	TeamID    *int64     `json:"team_id,omitempty"`
	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
}

type SLAPolicy struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"`
	DurationDays int       `json:"duration_days"`
	CreatedAt    time.Time `json:"created_at"`
}

type FindingAssignment struct {
	ID         int64      `json:"id"`
	FindingID  int64      `json:"finding_id"`
	TeamID     *int64     `json:"team_id,omitempty"`
	OwnerID    *int64     `json:"owner_id,omitempty"`
	Status     string     `json:"status"` // 'assigned', 'remediating', 'resolved', 'overdue'
	AssignedAt time.Time  `json:"assigned_at"`
	DueAt      time.Time  `json:"due_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

type EscalationRule struct {
	ID         int64                  `json:"id"`
	PolicyID   int64                  `json:"policy_id"`
	DelayDays  int                    `json:"delay_days"`
	ActionType string                 `json:"action_type"` // 'slack', 'email', 'webhook'
	Properties map[string]interface{} `json:"properties"`
	CreatedAt  time.Time              `json:"created_at"`
}

type OverdueAssignment struct {
	AssignmentID int64     `json:"assignment_id"`
	FindingID    int64     `json:"finding_id"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	Target       string    `json:"target"`
	TeamID       *int64    `json:"team_id,omitempty"`
	OwnerID      *int64    `json:"owner_id,omitempty"`
	DueAt        time.Time `json:"due_at"`
	Status       string    `json:"status"`
}

// AddTeam inserts a new team.
func (s *Storage) AddTeam(name string) (int64, error) {
	query := "INSERT INTO teams (name, created_at) VALUES (?, ?)"
	if s.dbType == "postgres" {
		query = "INSERT INTO teams (name, created_at) VALUES ($1, $2) RETURNING id"
		var id int64
		err := s.db.QueryRow(query, name, time.Now().UTC()).Scan(&id)
		return id, err
	}
	res, err := s.db.Exec(query, name, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetTeam retrieves a team by ID.
func (s *Storage) GetTeam(id int64) (*Team, error) {
	query := "SELECT id, name, created_at FROM teams WHERE id = ?"
	if s.dbType == "postgres" {
		query = "SELECT id, name, created_at FROM teams WHERE id = $1"
	}
	t := &Team{}
	err := s.db.QueryRow(query, id).Scan(&t.ID, &t.Name, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// AddOwner inserts a new owner.
func (s *Storage) AddOwner(name, email string) (int64, error) {
	query := "INSERT INTO owners (name, email, created_at) VALUES (?, ?, ?)"
	if s.dbType == "postgres" {
		query = "INSERT INTO owners (name, email, created_at) VALUES ($1, $2, $3) RETURNING id"
		var id int64
		err := s.db.QueryRow(query, name, email, time.Now().UTC()).Scan(&id)
		return id, err
	}
	res, err := s.db.Exec(query, name, email, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetOwner retrieves an owner by ID.
func (s *Storage) GetOwner(id int64) (*Owner, error) {
	query := "SELECT id, name, email, created_at FROM owners WHERE id = ?"
	if s.dbType == "postgres" {
		query = "SELECT id, name, email, created_at FROM owners WHERE id = $1"
	}
	o := &Owner{}
	err := s.db.QueryRow(query, id).Scan(&o.ID, &o.Name, &o.Email, &o.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

// SetAssetOwner sets the owner of an asset using SCD Type 2.
func (s *Storage) SetAssetOwner(assetID string, ownerID *int64, teamID *int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC()

	// 1. Close current active ownerships for this asset
	closeQuery := "UPDATE asset_ownership SET end_time = ? WHERE asset_id = ? AND end_time IS NULL"
	if s.dbType == "postgres" {
		closeQuery = "UPDATE asset_ownership SET end_time = $1 WHERE asset_id = $2 AND end_time IS NULL"
	}
	if _, err := tx.Exec(closeQuery, now, assetID); err != nil {
		return err
	}

	// 2. Insert new ownership record
	insertQuery := "INSERT INTO asset_ownership (asset_id, owner_id, team_id, start_time, end_time) VALUES (?, ?, ?, ?, ?)"
	if s.dbType == "postgres" {
		insertQuery = "INSERT INTO asset_ownership (asset_id, owner_id, team_id, start_time, end_time) VALUES ($1, $2, $3, $4, $5)"
	}
	if _, err := tx.Exec(insertQuery, assetID, ownerID, teamID, now, nil); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// 3. Mirror in asset graph nodes and edges
	s.syncOwnershipToGraph(assetID, ownerID, teamID)
	return nil
}

// GetAssetOwners retrieves all ownership records for an asset (both past and present).
func (s *Storage) GetAssetOwners(assetID string) ([]AssetOwnership, error) {
	query := "SELECT id, asset_id, owner_id, team_id, start_time, end_time FROM asset_ownership WHERE asset_id = ? ORDER BY start_time DESC"
	if s.dbType == "postgres" {
		query = "SELECT id, asset_id, owner_id, team_id, start_time, end_time FROM asset_ownership WHERE asset_id = $1 ORDER BY start_time DESC"
	}
	rows, err := s.db.Query(query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AssetOwnership
	for rows.Next() {
		var o AssetOwnership
		if err := rows.Scan(&o.ID, &o.AssetID, &o.OwnerID, &o.TeamID, &o.StartTime, &o.EndTime); err != nil {
			return nil, err
		}
		list = append(list, o)
	}
	return list, nil
}

// AddSLAPolicy inserts a new SLA policy.
func (s *Storage) AddSLAPolicy(name, severity string, durationDays int) (int64, error) {
	query := "INSERT INTO sla_policies (name, severity, duration_days, created_at) VALUES (?, ?, ?, ?)"
	if s.dbType == "postgres" {
		query = "INSERT INTO sla_policies (name, severity, duration_days, created_at) VALUES ($1, $2, $3, $4) RETURNING id"
		var id int64
		err := s.db.QueryRow(query, name, severity, durationDays, time.Now().UTC()).Scan(&id)
		return id, err
	}
	res, err := s.db.Exec(query, name, severity, durationDays, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetSLAPolicy retrieves an SLA policy by ID.
func (s *Storage) GetSLAPolicy(id int64) (*SLAPolicy, error) {
	query := "SELECT id, name, severity, duration_days, created_at FROM sla_policies WHERE id = ?"
	if s.dbType == "postgres" {
		query = "SELECT id, name, severity, duration_days, created_at FROM sla_policies WHERE id = $1"
	}
	p := &SLAPolicy{}
	err := s.db.QueryRow(query, id).Scan(&p.ID, &p.Name, &p.Severity, &p.DurationDays, &p.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return p, err
}

// AssignFinding assigns a finding to a team and/or owner and computes the due date based on SLA policies.
func (s *Storage) AssignFinding(findingID int64, teamID *int64, ownerID *int64, severity string) (int64, error) {
	// 1. Query SLA policy duration for severity
	policyQuery := "SELECT duration_days FROM sla_policies WHERE severity = ? ORDER BY id DESC LIMIT 1"
	if s.dbType == "postgres" {
		policyQuery = "SELECT duration_days FROM sla_policies WHERE severity = $1 ORDER BY id DESC LIMIT 1"
	}

	var durationDays int
	err := s.db.QueryRow(policyQuery, severity).Scan(&durationDays)
	if err == sql.ErrNoRows {
		// Default to 14 days if no SLA policy exists
		durationDays = 14
	} else if err != nil {
		return 0, err
	}

	now := time.Now().UTC()
	dueAt := now.AddDate(0, 0, durationDays)

	insertQuery := `
		INSERT INTO finding_assignments (finding_id, team_id, owner_id, status, assigned_at, due_at, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	var lastID int64
	if s.dbType == "postgres" {
		insertQuery = `
			INSERT INTO finding_assignments (finding_id, team_id, owner_id, status, assigned_at, due_at, resolved_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
		`
		err = s.db.QueryRow(insertQuery, findingID, teamID, ownerID, "assigned", now, dueAt, nil).Scan(&lastID)
	} else {
		res, errExec := s.db.Exec(insertQuery, findingID, teamID, ownerID, "assigned", now, dueAt, nil)
		if errExec != nil {
			return 0, errExec
		}
		lastID, err = res.LastInsertId()
	}

	if err != nil {
		return 0, err
	}

	// 2. Mirror assignment to the graph
	s.syncAssignmentToGraph(findingID, teamID, ownerID)
	return lastID, nil
}

// UpdateAssignmentStatus updates status and resolved_at timestamp.
func (s *Storage) UpdateAssignmentStatus(id int64, status string) error {
	var query string
	now := time.Now().UTC()
	if status == "resolved" {
		query = "UPDATE finding_assignments SET status = ?, resolved_at = ? WHERE id = ?"
		if s.dbType == "postgres" {
			query = "UPDATE finding_assignments SET status = $1, resolved_at = $2 WHERE id = $3"
		}
		_, err := s.db.Exec(query, status, now, id)
		return err
	}

	query = "UPDATE finding_assignments SET status = ? WHERE id = ?"
	if s.dbType == "postgres" {
		query = "UPDATE finding_assignments SET status = $1 WHERE id = $2"
	}
	_, err := s.db.Exec(query, status, id)
	return err
}

// GetOverdueAssignments queries assignments that have passed their due_at date.
func (s *Storage) GetOverdueAssignments() ([]OverdueAssignment, error) {
	query := `
		SELECT fa.id, fa.finding_id, f.title, f.severity, f.target, fa.team_id, fa.owner_id, fa.due_at, fa.status
		FROM finding_assignments fa
		JOIN findings f ON fa.finding_id = f.id
		WHERE fa.status != 'resolved' AND fa.due_at < ?
	`
	if s.dbType == "postgres" {
		query = `
			SELECT fa.id, fa.finding_id, f.title, f.severity, f.target, fa.team_id, fa.owner_id, fa.due_at, fa.status
			FROM finding_assignments fa
			JOIN findings f ON fa.finding_id = f.id
			WHERE fa.status != 'resolved' AND fa.due_at < $1
		`
	}
	rows, err := s.db.Query(query, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []OverdueAssignment
	for rows.Next() {
		var oa OverdueAssignment
		if err := rows.Scan(&oa.AssignmentID, &oa.FindingID, &oa.Title, &oa.Severity, &oa.Target, &oa.TeamID, &oa.OwnerID, &oa.DueAt, &oa.Status); err != nil {
			return nil, err
		}
		list = append(list, oa)
	}
	return list, nil
}

// AddEscalationRule adds a new escalation rule under a policy.
func (s *Storage) AddEscalationRule(policyID int64, delayDays int, actionType string, properties map[string]interface{}) (int64, error) {
	propsJSON, err := json.Marshal(properties)
	if err != nil {
		return 0, err
	}

	query := "INSERT INTO escalation_rules (policy_id, delay_days, action_type, properties, created_at) VALUES (?, ?, ?, ?, ?)"
	if s.dbType == "postgres" {
		query = "INSERT INTO escalation_rules (policy_id, delay_days, action_type, properties, created_at) VALUES ($1, $2, $3, $4, $5) RETURNING id"
		var id int64
		err := s.db.QueryRow(query, policyID, delayDays, actionType, string(propsJSON), time.Now().UTC()).Scan(&id)
		return id, err
	}
	res, err := s.db.Exec(query, policyID, delayDays, actionType, string(propsJSON), time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetEscalationRules retrieves all escalation rules for a policy.
func (s *Storage) GetEscalationRules(policyID int64) ([]EscalationRule, error) {
	query := "SELECT id, policy_id, delay_days, action_type, properties, created_at FROM escalation_rules WHERE policy_id = ? ORDER BY delay_days ASC"
	if s.dbType == "postgres" {
		query = "SELECT id, policy_id, delay_days, action_type, properties, created_at FROM escalation_rules WHERE policy_id = $1 ORDER BY delay_days ASC"
	}
	rows, err := s.db.Query(query, policyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []EscalationRule
	for rows.Next() {
		var er EscalationRule
		var propsJSON string
		if err := rows.Scan(&er.ID, &er.PolicyID, &er.DelayDays, &er.ActionType, &propsJSON, &er.CreatedAt); err != nil {
			return nil, err
		}
		if propsJSON != "" {
			_ = json.Unmarshal([]byte(propsJSON), &er.Properties)
		}
		list = append(list, er)
	}
	return list, nil
}

func (s *Storage) syncOwnershipToGraph(assetID string, ownerID *int64, teamID *int64) {
	assetNodeID := GenerateNodeID("target", assetID)
	_, _ = s.SaveNode("target", assetID, nil)

	if ownerID != nil {
		owner, err := s.GetOwner(*ownerID)
		if err == nil && owner != nil {
			ownerNodeID, err := s.SaveNode("owner", owner.Email, map[string]string{
				"name": owner.Name,
			})
			if err == nil {
				_ = s.SaveEdge(assetNodeID, ownerNodeID, "owned_by_owner")
			}
		}
	}

	if teamID != nil {
		team, err := s.GetTeam(*teamID)
		if err == nil && team != nil {
			teamNodeID, err := s.SaveNode("team", team.Name, nil)
			if err == nil {
				_ = s.SaveEdge(assetNodeID, teamNodeID, "owned_by_team")

				if ownerID != nil {
					owner, err := s.GetOwner(*ownerID)
					if err == nil && owner != nil {
						ownerNodeID, errOwner := s.SaveNode("owner", owner.Email, map[string]string{"name": owner.Name})
						if errOwner == nil {
							_ = s.SaveEdge(ownerNodeID, teamNodeID, "member_of")
						}
					}
				}
			}
		}
	}
}

func (s *Storage) syncAssignmentToGraph(findingID int64, teamID *int64, ownerID *int64) {
	var target, title string
	err := s.db.QueryRow("SELECT target, title FROM findings WHERE id = ?", findingID).Scan(&target, &title)
	if s.dbType == "postgres" {
		err = s.db.QueryRow("SELECT target, title FROM findings WHERE id = $1", findingID).Scan(&target, &title)
	}
	if err != nil {
		return
	}

	findingNodeID, err := s.SaveNode("vulnerability", title, map[string]string{
		"finding_id": fmt.Sprintf("%d", findingID),
		"target":     target,
	})
	if err != nil {
		return
	}

	// Link finding/vuln to target/asset
	targetNodeID := GenerateNodeID("target", target)
	_ = s.SaveEdge(targetNodeID, findingNodeID, "is_vulnerable_to")

	if ownerID != nil {
		owner, err := s.GetOwner(*ownerID)
		if err == nil && owner != nil {
			ownerNodeID, err := s.SaveNode("owner", owner.Email, map[string]string{
				"name": owner.Name,
			})
			if err == nil {
				_ = s.SaveEdge(findingNodeID, ownerNodeID, "assigned_to_owner")
			}
		}
	}

	if teamID != nil {
		team, err := s.GetTeam(*teamID)
		if err == nil && team != nil {
			teamNodeID, err := s.SaveNode("team", team.Name, nil)
			if err == nil {
				_ = s.SaveEdge(findingNodeID, teamNodeID, "assigned_to_team")
			}
		}
	}
}

// GetEscalationRulesForSeverity queries all escalation rules linked to a policy of a given severity.
func (s *Storage) GetEscalationRulesForSeverity(severity string) ([]EscalationRule, error) {
	query := `
		SELECT er.id, er.policy_id, er.delay_days, er.action_type, er.properties, er.created_at
		FROM escalation_rules er
		JOIN sla_policies sp ON er.policy_id = sp.id
		WHERE sp.severity = ?
		ORDER BY er.delay_days ASC
	`
	if s.dbType == "postgres" {
		query = `
			SELECT er.id, er.policy_id, er.delay_days, er.action_type, er.properties, er.created_at
			FROM escalation_rules er
			JOIN sla_policies sp ON er.policy_id = sp.id
			WHERE sp.severity = $1
			ORDER BY er.delay_days ASC
		`
	}
	rows, err := s.db.Query(query, severity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []EscalationRule
	for rows.Next() {
		var er EscalationRule
		var propsJSON string
		if err := rows.Scan(&er.ID, &er.PolicyID, &er.DelayDays, &er.ActionType, &propsJSON, &er.CreatedAt); err != nil {
			return nil, err
		}
		if propsJSON != "" {
			_ = json.Unmarshal([]byte(propsJSON), &er.Properties)
		}
		list = append(list, er)
	}
	return list, nil
}

// AddFindingForTest inserts a mock finding for unit testing purposes.
func (s *Storage) AddFindingForTest(title, description, severity, target string) (int64, error) {
	query := `
		INSERT INTO findings (title, description, severity, target, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	if s.dbType == "postgres" {
		query = `
			INSERT INTO findings (title, description, severity, target, metadata, created_at)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id
		`
		var id int64
		err := s.db.QueryRow(query, title, description, severity, target, "", time.Now().UTC()).Scan(&id)
		return id, err
	}

	res, err := s.db.Exec(query, title, description, severity, target, "", time.Now().UTC())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ForceAssignmentOverdueForTest updates a finding assignment's due date to be in the past for testing.
func (s *Storage) ForceAssignmentOverdueForTest(assignmentID int64, overdueDuration time.Duration) error {
	query := "UPDATE finding_assignments SET due_at = ? WHERE id = ?"
	if s.dbType == "postgres" {
		query = "UPDATE finding_assignments SET due_at = $1 WHERE id = $2"
	}
	pastTime := time.Now().UTC().Add(-overdueDuration)
	_, err := s.db.Exec(query, pastTime, assignmentID)
	return err
}

// GetAssignmentStatusForTest returns the current status of an assignment for testing.
func (s *Storage) GetAssignmentStatusForTest(assignmentID int64) (string, error) {
	query := "SELECT status FROM finding_assignments WHERE id = ?"
	if s.dbType == "postgres" {
		query = "SELECT status FROM finding_assignments WHERE id = $1"
	}
	var status string
	err := s.db.QueryRow(query, assignmentID).Scan(&status)
	return status, err
}
