package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Team struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	ManagerID *int64    `json:"manager_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Owner struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email"`
	ManagerID *int64    `json:"manager_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AssetOwnership struct {
	ID           int64      `json:"id"`
	AssetID      string     `json:"asset_id"`
	OwnerID      *int64     `json:"owner_id,omitempty"`
	TeamID       *int64     `json:"team_id,omitempty"`
	StartTime    time.Time  `json:"start_time"`
	EndTime      *time.Time `json:"end_time,omitempty"`
	ChangeReason string     `json:"change_reason,omitempty"`
}

type SLAPolicy struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	Severity     string    `json:"severity"`
	DurationDays int       `json:"duration_days"`
	CreatedAt    time.Time `json:"created_at"`
	AssetClass   string    `json:"asset_class,omitempty"`
	BusinessUnit string    `json:"business_unit,omitempty"`
	Environment  string    `json:"environment,omitempty"`
	Program      string    `json:"program,omitempty"`
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
	query := "SELECT id, name, manager_id, created_at FROM teams WHERE id = ?"
	if s.dbType == "postgres" {
		query = "SELECT id, name, manager_id, created_at FROM teams WHERE id = $1"
	}
	t := &Team{}
	err := s.db.QueryRow(query, id).Scan(&t.ID, &t.Name, &t.ManagerID, &t.CreatedAt)
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
	query := "SELECT id, name, email, manager_id, created_at FROM owners WHERE id = ?"
	if s.dbType == "postgres" {
		query = "SELECT id, name, email, manager_id, created_at FROM owners WHERE id = $1"
	}
	o := &Owner{}
	err := s.db.QueryRow(query, id).Scan(&o.ID, &o.Name, &o.Email, &o.ManagerID, &o.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return o, err
}

// SetOwnerManager updates an owner's manager reporting relationship.
func (s *Storage) SetOwnerManager(ownerID, managerID int64) error {
	query := "UPDATE owners SET manager_id = ? WHERE id = ?"
	if s.dbType == "postgres" {
		query = "UPDATE owners SET manager_id = $1 WHERE id = $2"
	}
	_, err := s.db.Exec(query, managerID, ownerID)
	return err
}

// SetTeamManager updates a team's manager.
func (s *Storage) SetTeamManager(teamID, managerID int64) error {
	query := "UPDATE teams SET manager_id = ? WHERE id = ?"
	if s.dbType == "postgres" {
		query = "UPDATE teams SET manager_id = $1 WHERE id = $2"
	}
	_, err := s.db.Exec(query, managerID, teamID)
	return err
}

// SetAssetOwner sets the owner of an asset using SCD Type 2.
func (s *Storage) SetAssetOwner(assetID string, ownerID *int64, teamID *int64, changeReason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

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
	insertQuery := "INSERT INTO asset_ownership (asset_id, owner_id, team_id, start_time, end_time, change_reason) VALUES (?, ?, ?, ?, ?, ?)"
	if s.dbType == "postgres" {
		insertQuery = "INSERT INTO asset_ownership (asset_id, owner_id, team_id, start_time, end_time, change_reason) VALUES ($1, $2, $3, $4, $5, $6)"
	}
	if _, err := tx.Exec(insertQuery, assetID, ownerID, teamID, now, nil, changeReason); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	// 3. Mirror in asset graph nodes and edges
	if err := s.syncOwnershipToGraph(assetID, ownerID, teamID); err != nil {
		return fmt.Errorf("failed to sync ownership to graph: %w", err)
	}
	return nil
}

// GetAssetOwners retrieves all ownership records for an asset (both past and present).
func (s *Storage) GetAssetOwners(assetID string) ([]AssetOwnership, error) {
	query := "SELECT id, asset_id, owner_id, team_id, start_time, end_time, change_reason FROM asset_ownership WHERE asset_id = ? ORDER BY start_time DESC"
	if s.dbType == "postgres" {
		query = "SELECT id, asset_id, owner_id, team_id, start_time, end_time, change_reason FROM asset_ownership WHERE asset_id = $1 ORDER BY start_time DESC"
	}
	rows, err := s.db.Query(query, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AssetOwnership
	for rows.Next() {
		var o AssetOwnership
		var cr sql.NullString
		if err := rows.Scan(&o.ID, &o.AssetID, &o.OwnerID, &o.TeamID, &o.StartTime, &o.EndTime, &cr); err != nil {
			return nil, err
		}
		if cr.Valid {
			o.ChangeReason = cr.String
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
	query := "SELECT id, name, severity, duration_days, created_at, asset_class, business_unit, environment, program FROM sla_policies WHERE id = ?"
	if s.dbType == "postgres" {
		query = "SELECT id, name, severity, duration_days, created_at, asset_class, business_unit, environment, program FROM sla_policies WHERE id = $1"
	}
	p := &SLAPolicy{}
	var ac, bu, env, prog sql.NullString
	err := s.db.QueryRow(query, id).Scan(&p.ID, &p.Name, &p.Severity, &p.DurationDays, &p.CreatedAt, &ac, &bu, &env, &prog)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.AssetClass = ac.String
	p.BusinessUnit = bu.String
	p.Environment = env.String
	p.Program = prog.String
	return p, nil
}

// AddSLAPolicyExt inserts a new SLA policy with rich matching criteria.
func (s *Storage) AddSLAPolicyExt(name, severity string, durationDays int, assetClass, businessUnit, environment, program string) (int64, error) {
	query := "INSERT INTO sla_policies (name, severity, duration_days, created_at, asset_class, business_unit, environment, program) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
	if s.dbType == "postgres" {
		query = "INSERT INTO sla_policies (name, severity, duration_days, created_at, asset_class, business_unit, environment, program) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id"
		var id int64
		err := s.db.QueryRow(query, name, severity, durationDays, time.Now().UTC(), assetClass, businessUnit, environment, program).Scan(&id)
		return id, err
	}
	res, err := s.db.Exec(query, name, severity, durationDays, time.Now().UTC(), assetClass, businessUnit, environment, program)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetMatchingSLAPolicy matches SLA policy using the most specific criteria.
func (s *Storage) GetMatchingSLAPolicy(severity, assetClass, businessUnit, environment, program string) (*SLAPolicy, error) {
	query := `
		SELECT id, name, severity, duration_days, created_at, asset_class, business_unit, environment, program
		FROM sla_policies
		WHERE severity = ?
		  AND (asset_class IS NULL OR asset_class = ? OR asset_class = '')
		  AND (business_unit IS NULL OR business_unit = ? OR business_unit = '')
		  AND (environment IS NULL OR environment = ? OR environment = '')
		  AND (program IS NULL OR program = ? OR program = '')
		ORDER BY
		  (CASE WHEN asset_class = ? THEN 1 ELSE 0 END +
		   CASE WHEN business_unit = ? THEN 1 ELSE 0 END +
		   CASE WHEN environment = ? THEN 1 ELSE 0 END +
		   CASE WHEN program = ? THEN 1 ELSE 0 END) DESC, id DESC
		LIMIT 1
	`
	if s.dbType == "postgres" {
		query = `
			SELECT id, name, severity, duration_days, created_at, asset_class, business_unit, environment, program
			FROM sla_policies
			WHERE severity = $1
			  AND (asset_class IS NULL OR asset_class = $2 OR asset_class = '')
			  AND (business_unit IS NULL OR business_unit = $3 OR business_unit = '')
			  AND (environment IS NULL OR environment = $4 OR environment = '')
			  AND (program IS NULL OR program = $5 OR program = '')
			ORDER BY
			  (CASE WHEN asset_class = $2 THEN 1 ELSE 0 END +
			   CASE WHEN business_unit = $3 THEN 1 ELSE 0 END +
			   CASE WHEN environment = $4 THEN 1 ELSE 0 END +
			   CASE WHEN program = $5 THEN 1 ELSE 0 END) DESC, id DESC
			LIMIT 1
		`
	}

	p := &SLAPolicy{}
	var ac, bu, env, prog sql.NullString
	var err error
	if s.dbType == "postgres" {
		err = s.db.QueryRow(query, severity, assetClass, businessUnit, environment, program).Scan(&p.ID, &p.Name, &p.Severity, &p.DurationDays, &p.CreatedAt, &ac, &bu, &env, &prog)
	} else {
		err = s.db.QueryRow(query, severity, assetClass, businessUnit, environment, program, assetClass, businessUnit, environment, program).Scan(&p.ID, &p.Name, &p.Severity, &p.DurationDays, &p.CreatedAt, &ac, &bu, &env, &prog)
	}
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.AssetClass = ac.String
	p.BusinessUnit = bu.String
	p.Environment = env.String
	p.Program = prog.String
	return p, nil
}

// AssignFinding assigns a finding to a team and/or owner and computes the due date based on SLA policies.
func (s *Storage) AssignFinding(findingID int64, teamID *int64, ownerID *int64, severity string) (int64, error) {
	// Query the target from the finding in db
	var target string
	err := s.db.QueryRow("SELECT target FROM findings WHERE id = ?", findingID).Scan(&target)
	if s.dbType == "postgres" {
		err = s.db.QueryRow("SELECT target FROM findings WHERE id = $1", findingID).Scan(&target)
	}
	if err != nil {
		return 0, err
	}

	// Fetch target node properties to extract matching criteria
	var assetClass, businessUnit, environment, program string
	targetNodeID := GenerateNodeID("target", target, "")
	var propsJSON string
	err = s.db.QueryRow("SELECT properties FROM asset_nodes WHERE id = ?", targetNodeID).Scan(&propsJSON)
	if s.dbType == "postgres" {
		err = s.db.QueryRow("SELECT properties FROM asset_nodes WHERE id = $1", targetNodeID).Scan(&propsJSON)
	}
	if err == nil && propsJSON != "" {
		var props map[string]string
		if json.Unmarshal([]byte(propsJSON), &props) == nil {
			assetClass = props["asset_class"]
			businessUnit = props["business_unit"]
			environment = props["environment"]
			program = props["program"]
		}
	}

	// Match the most specific SLA policy
	durationDays := 14
	policy, err := s.GetMatchingSLAPolicy(severity, assetClass, businessUnit, environment, program)
	if err == nil && policy != nil {
		durationDays = policy.DurationDays
	}

	now := time.Now().UTC()
	dueAt := now.AddDate(0, 0, durationDays)

	insertQuery := `
		INSERT INTO finding_assignments (finding_id, team_id, owner_id, status, assigned_at, due_at, resolved_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var lastID int64
	if s.dbType == "postgres" {
		insertQuery = `
			INSERT INTO finding_assignments (finding_id, team_id, owner_id, status, assigned_at, due_at, resolved_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id
		`
		err = tx.QueryRow(insertQuery, findingID, teamID, ownerID, "Assigned", now, dueAt, nil).Scan(&lastID)
	} else {
		res, errExec := tx.Exec(insertQuery, findingID, teamID, ownerID, "Assigned", now, dueAt, nil)
		if errExec != nil {
			return 0, errExec
		}
		lastID, err = res.LastInsertId()
	}

	if err != nil {
		return 0, err
	}

	historyQuery := `
		INSERT INTO finding_status_history (finding_id, old_status, new_status, changed_at, comment, changed_by)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	if s.dbType == "postgres" {
		historyQuery = `
			INSERT INTO finding_status_history (finding_id, old_status, new_status, changed_at, comment, changed_by)
			VALUES ($1, $2, $3, $4, $5, $6)
		`
	}
	if _, err := tx.Exec(historyQuery, findingID, "Discovered", "Assigned", now, "Initial assignment", "system"); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	// 2. Mirror assignment to the graph
	if err := s.syncAssignmentToGraph(findingID, teamID, ownerID); err != nil {
		return lastID, fmt.Errorf("failed to sync assignment to graph: %w", err)
	}
	return lastID, nil
}

// UpdateAssignmentStatus updates status and resolved_at timestamp.
func (s *Storage) UpdateAssignmentStatus(id int64, status string) error {
	normalized := normalizeCTEMState(status)

	// Fetch current status and finding_id
	var oldStatus string
	var findingID int64
	var querySelect string
	if s.dbType == "postgres" {
		querySelect = "SELECT status, finding_id FROM finding_assignments WHERE id = $1"
	} else {
		querySelect = "SELECT status, finding_id FROM finding_assignments WHERE id = ?"
	}
	err := s.db.QueryRow(querySelect, id).Scan(&oldStatus, &findingID)
	if err != nil {
		return err
	}

	normalizedOld := normalizeCTEMState(oldStatus)
	if !isValidTransition(normalizedOld, normalized) {
		return fmt.Errorf("invalid CTEM state transition from %s to %s", normalizedOld, normalized)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	var queryUpdate string
	if normalized == "Verified" {
		if s.dbType == "postgres" {
			queryUpdate = "UPDATE finding_assignments SET status = $1, resolved_at = $2 WHERE id = $3"
		} else {
			queryUpdate = "UPDATE finding_assignments SET status = ?, resolved_at = ? WHERE id = ?"
		}
		if _, err := tx.Exec(queryUpdate, normalized, now, id); err != nil {
			return err
		}
	} else {
		if s.dbType == "postgres" {
			queryUpdate = "UPDATE finding_assignments SET status = $1 WHERE id = $2"
		} else {
			queryUpdate = "UPDATE finding_assignments SET status = ? WHERE id = ?"
		}
		if _, err := tx.Exec(queryUpdate, normalized, id); err != nil {
			return err
		}
	}

	// Insert status history record
	historyQuery := `
		INSERT INTO finding_status_history (finding_id, old_status, new_status, changed_at, comment, changed_by)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	if s.dbType == "postgres" {
		historyQuery = `
			INSERT INTO finding_status_history (finding_id, old_status, new_status, changed_at, comment, changed_by)
			VALUES ($1, $2, $3, $4, $5, $6)
		`
	}
	if _, err := tx.Exec(historyQuery, findingID, normalizeCTEMState(oldStatus), normalized, now, "Status updated", "system"); err != nil {
		return err
	}

	return tx.Commit()
}

// GetOverdueAssignments queries assignments that have passed their due_at date.
func (s *Storage) GetOverdueAssignments() ([]OverdueAssignment, error) {
	query := `
		SELECT fa.id, fa.finding_id, f.title, f.severity, f.target, fa.team_id, fa.owner_id, fa.due_at, fa.status
		FROM finding_assignments fa
		JOIN findings f ON fa.finding_id = f.id
		WHERE fa.status NOT IN ('resolved', 'Verified') AND fa.due_at < ?
	`
	if s.dbType == "postgres" {
		query = `
			SELECT fa.id, fa.finding_id, f.title, f.severity, f.target, fa.team_id, fa.owner_id, fa.due_at, fa.status
			FROM finding_assignments fa
			JOIN findings f ON fa.finding_id = f.id
			WHERE fa.status NOT IN ('resolved', 'Verified') AND fa.due_at < $1
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

func (s *Storage) syncOwnershipToGraph(assetID string, ownerID *int64, teamID *int64) error {
	assetNodeID, err := s.SaveNode("target", assetID, nil, "", "", 1.0)
	if err != nil {
		return fmt.Errorf("failed to save asset node: %w", err)
	}

	if ownerID != nil {
		owner, err := s.GetOwner(*ownerID)
		if err != nil {
			return fmt.Errorf("failed to get owner: %w", err)
		}
		if owner != nil {
			ownerNodeID, err := s.SaveNode("owner", owner.Email, map[string]string{
				"name": owner.Name,
			}, "", "", 1.0)
			if err != nil {
				return fmt.Errorf("failed to save owner node: %w", err)
			}
			if err := s.SaveEdge(assetNodeID, ownerNodeID, "owned_by_owner", 1.0, ""); err != nil {
				return fmt.Errorf("failed to save owned_by_owner edge: %w", err)
			}
			if err := s.SaveEdge(ownerNodeID, assetNodeID, "owns", 1.0, ""); err != nil {
				return fmt.Errorf("failed to save owns edge: %w", err)
			}
		}
	}

	if teamID != nil {
		team, err := s.GetTeam(*teamID)
		if err != nil {
			return fmt.Errorf("failed to get team: %w", err)
		}
		if team != nil {
			teamNodeID, err := s.SaveNode("team", team.Name, nil, "", "", 1.0)
			if err != nil {
				return fmt.Errorf("failed to save team node: %w", err)
			}
			if err := s.SaveEdge(assetNodeID, teamNodeID, "owned_by_team", 1.0, ""); err != nil {
				return fmt.Errorf("failed to save owned_by_team edge: %w", err)
			}
			if err := s.SaveEdge(teamNodeID, assetNodeID, "owns", 1.0, ""); err != nil {
				return fmt.Errorf("failed to save owns edge: %w", err)
			}

			if ownerID != nil {
				owner, err := s.GetOwner(*ownerID)
				if err != nil {
					return fmt.Errorf("failed to get owner for team: %w", err)
				}
				if owner != nil {
					ownerNodeID, errOwner := s.SaveNode("owner", owner.Email, map[string]string{"name": owner.Name}, "", "", 1.0)
					if errOwner != nil {
						return fmt.Errorf("failed to save owner node for team membership: %w", errOwner)
					}
					if err := s.SaveEdge(ownerNodeID, teamNodeID, "member_of", 1.0, ""); err != nil {
						return fmt.Errorf("failed to save member_of edge: %w", err)
					}
				}
			}
		}
	}
	return nil
}

func (s *Storage) syncAssignmentToGraph(findingID int64, teamID *int64, ownerID *int64) error {
	var target, title string
	err := s.db.QueryRow("SELECT target, title FROM findings WHERE id = ?", findingID).Scan(&target, &title)
	if s.dbType == "postgres" {
		err = s.db.QueryRow("SELECT target, title FROM findings WHERE id = $1", findingID).Scan(&target, &title)
	}
	if err != nil {
		return fmt.Errorf("failed to query finding %d: %w", findingID, err)
	}

	findingNodeID, err := s.SaveNode("vulnerability", title, map[string]string{
		"finding_id": fmt.Sprintf("%d", findingID),
		"target":     target,
	}, "", "", 1.0)
	if err != nil {
		return fmt.Errorf("failed to save finding node: %w", err)
	}

	// Link finding/vuln to target/asset
	targetNodeID := GenerateNodeID("target", target, "")
	if err := s.SaveEdge(targetNodeID, findingNodeID, "is_vulnerable_to", 1.0, ""); err != nil {
		return fmt.Errorf("failed to save is_vulnerable_to edge: %w", err)
	}

	if ownerID != nil {
		owner, err := s.GetOwner(*ownerID)
		if err != nil {
			return fmt.Errorf("failed to get owner: %w", err)
		}
		if owner != nil {
			ownerNodeID, err := s.SaveNode("owner", owner.Email, map[string]string{
				"name": owner.Name,
			}, "", "", 1.0)
			if err != nil {
				return fmt.Errorf("failed to save owner node: %w", err)
			}
			if err := s.SaveEdge(findingNodeID, ownerNodeID, "assigned_to_owner", 1.0, ""); err != nil {
				return fmt.Errorf("failed to save assigned_to_owner edge: %w", err)
			}
		}
	}

	if teamID != nil {
		team, err := s.GetTeam(*teamID)
		if err != nil {
			return fmt.Errorf("failed to get team: %w", err)
		}
		if team != nil {
			teamNodeID, err := s.SaveNode("team", team.Name, nil, "", "", 1.0)
			if err != nil {
				return fmt.Errorf("failed to save team node: %w", err)
			}
			if err := s.SaveEdge(findingNodeID, teamNodeID, "assigned_to_team", 1.0, ""); err != nil {
				return fmt.Errorf("failed to save assigned_to_team edge: %w", err)
			}
		}
	}
	return nil
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

type FindingStatusHistory struct {
	ID        int64     `json:"id"`
	FindingID int64     `json:"finding_id"`
	OldStatus string    `json:"old_status"`
	NewStatus string    `json:"new_status"`
	ChangedAt time.Time `json:"changed_at"`
	Comment   string    `json:"comment"`
	ChangedBy string    `json:"changed_by"`
}

func normalizeCTEMState(status string) string {
	lower := strings.ToLower(status)
	switch lower {
	case "discovered":
		return "Discovered"
	case "triaged":
		return "Triaged"
	case "assigned":
		return "Assigned"
	case "remediating":
		return "Remediating"
	case "acknowledged":
		return "Acknowledged"
	case "remediated":
		return "Remediated"
	case "resolved", "verified":
		return "Verified"
	case "reopened":
		return "Reopened"
	case "exempted", "sla exception", "sla_exception":
		return "SLA Exception"
	case "expired":
		return "Expired"
	case "overdue":
		return "Overdue"
	default:
		// Handle escalated_lvl_N states (preserve level number)
		if strings.HasPrefix(lower, "escalated_lvl_") {
			return status
		}
		return status
	}
}

func isEscalatedState(s string) bool {
	return strings.HasPrefix(strings.ToLower(s), "escalated_lvl_")
}

func isValidTransition(from, to string) bool {
	if from == to {
		return true
	}

	// Escalation-level states can always promote to higher levels,
	// move to Remediated/Remediating, or be Acknowledged/SLA Exception.
	if isEscalatedState(from) {
		return isEscalatedState(to) || to == "Remediated" || to == "Remediating" || to == "Acknowledged" || to == "SLA Exception"
	}

	switch from {
	case "Discovered":
		return to == "Triaged" || to == "Assigned" || to == "SLA Exception"
	case "Triaged":
		return to == "Assigned" || to == "SLA Exception"
	case "Assigned":
		return to == "Acknowledged" || to == "Remediating" || to == "SLA Exception" || to == "Expired" ||
			to == "Overdue" || isEscalatedState(to)
	case "Acknowledged":
		return to == "Remediating" || to == "Remediated" || to == "Assigned" || to == "SLA Exception" || to == "Expired" ||
			to == "Overdue" || isEscalatedState(to)
	case "Remediating":
		return to == "Remediated" || to == "Assigned" || to == "SLA Exception" || to == "Expired" ||
			to == "Overdue" || isEscalatedState(to)
	case "Overdue":
		return isEscalatedState(to) || to == "Remediated" || to == "Remediating" || to == "Acknowledged" || to == "SLA Exception"
	case "Remediated":
		return to == "Verified" || to == "Reopened"
	case "Verified":
		return to == "Reopened"
	case "SLA Exception":
		return to == "Expired" || to == "Reopened" || to == "Assigned" || to == "Remediating" || to == "Remediated"
	case "Expired":
		return to == "Reopened" || to == "Assigned"
	case "Reopened":
		return to == "Assigned" || to == "Triaged" || to == "SLA Exception"
	default:
		// Default fallback for any other transition (like empty/uninitialized legacy states)
		return true
	}
}

// GetFindingStatusHistory retrieves the status history for a finding.
func (s *Storage) GetFindingStatusHistory(findingID int64) ([]FindingStatusHistory, error) {
	query := `
		SELECT id, finding_id, old_status, new_status, changed_at, COALESCE(comment, ''), COALESCE(changed_by, '')
		FROM finding_status_history
		WHERE finding_id = ?
		ORDER BY changed_at ASC
	`
	if s.dbType == "postgres" {
		query = `
			SELECT id, finding_id, old_status, new_status, changed_at, COALESCE(comment, ''), COALESCE(changed_by, '')
			FROM finding_status_history
			WHERE finding_id = $1
			ORDER BY changed_at ASC
		`
	}

	rows, err := s.db.Query(query, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []FindingStatusHistory
	for rows.Next() {
		var h FindingStatusHistory
		if err := rows.Scan(&h.ID, &h.FindingID, &h.OldStatus, &h.NewStatus, &h.ChangedAt, &h.Comment, &h.ChangedBy); err != nil {
			return nil, err
		}
		h.ChangedAt = h.ChangedAt.UTC()
		list = append(list, h)
	}
	return list, nil
}

// UpdateAssignmentStatusWithComment updates status, resolved_at timestamp, and writes to history with a custom comment and changed_by fields.
func (s *Storage) UpdateAssignmentStatusWithComment(id int64, status string, comment string, changedBy string) error {
	normalized := normalizeCTEMState(status)

	// Fetch current status and finding_id
	var oldStatus string
	var findingID int64
	var querySelect string
	if s.dbType == "postgres" {
		querySelect = "SELECT status, finding_id FROM finding_assignments WHERE id = $1"
	} else {
		querySelect = "SELECT status, finding_id FROM finding_assignments WHERE id = ?"
	}
	err := s.db.QueryRow(querySelect, id).Scan(&oldStatus, &findingID)
	if err != nil {
		return err
	}

	normalizedOld := normalizeCTEMState(oldStatus)
	if !isValidTransition(normalizedOld, normalized) {
		return fmt.Errorf("invalid CTEM state transition from %s to %s", normalizedOld, normalized)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	now := time.Now().UTC()
	var queryUpdate string
	if normalized == "Verified" {
		if s.dbType == "postgres" {
			queryUpdate = "UPDATE finding_assignments SET status = $1, resolved_at = $2 WHERE id = $3"
		} else {
			queryUpdate = "UPDATE finding_assignments SET status = ?, resolved_at = ? WHERE id = ?"
		}
		if _, err := tx.Exec(queryUpdate, normalized, now, id); err != nil {
			return err
		}
	} else {
		if s.dbType == "postgres" {
			queryUpdate = "UPDATE finding_assignments SET status = $1 WHERE id = $2"
		} else {
			queryUpdate = "UPDATE finding_assignments SET status = ? WHERE id = ?"
		}
		if _, err := tx.Exec(queryUpdate, normalized, id); err != nil {
			return err
		}
	}

	// Insert status history record
	historyQuery := `
		INSERT INTO finding_status_history (finding_id, old_status, new_status, changed_at, comment, changed_by)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	if s.dbType == "postgres" {
		historyQuery = `
			INSERT INTO finding_status_history (finding_id, old_status, new_status, changed_at, comment, changed_by)
			VALUES ($1, $2, $3, $4, $5, $6)
		`
	}
	if _, err := tx.Exec(historyQuery, findingID, normalizeCTEMState(oldStatus), normalized, now, comment, changedBy); err != nil {
		return err
	}

	return tx.Commit()
}

// VerifyFindingFix transitions a finding assignment to "Verified" with a verification comment and recorder.
func (s *Storage) VerifyFindingFix(id int64, comment string, verifiedBy string) error {
	var oldStatus string
	var querySelect string
	if s.dbType == "postgres" {
		querySelect = "SELECT status FROM finding_assignments WHERE id = $1"
	} else {
		querySelect = "SELECT status FROM finding_assignments WHERE id = ?"
	}
	err := s.db.QueryRow(querySelect, id).Scan(&oldStatus)
	if err != nil {
		return err
	}

	normalizedOld := normalizeCTEMState(oldStatus)
	if normalizedOld != "Remediated" {
		if !isValidTransition(normalizedOld, "Remediated") {
			// Try transitioning to Remediating first
			if err := s.UpdateAssignmentStatusWithComment(id, "Remediating", "Auto-transitioning to Remediating prior to fix verification", verifiedBy); err != nil {
				return fmt.Errorf("transition to Remediating failed: %w", err)
			}
		}
		// Now transition to Remediated
		if err := s.UpdateAssignmentStatusWithComment(id, "Remediated", "Marking as remediated for verification", verifiedBy); err != nil {
			return fmt.Errorf("transition to Remediated failed: %w", err)
		}
	}

	return s.UpdateAssignmentStatusWithComment(id, "Verified", comment, verifiedBy)
}

// ApproveRiskException transitions a finding assignment to "SLA Exception" with risk approval details.
func (s *Storage) ApproveRiskException(id int64, comment string, approvedBy string) error {
	return s.UpdateAssignmentStatusWithComment(id, "SLA Exception", comment, approvedBy)
}

type ScanFinding struct {
	Title    string
	Target   string
	Severity string
}

// AutoTransitionFindingStates automates assignment status updates based on scanner re-detections.
func (s *Storage) AutoTransitionFindingStates(detected []ScanFinding, scannedTargets []string) error {
	detectedMap := make(map[string]bool)
	for _, f := range detected {
		key := fmt.Sprintf("%s:%s", f.Target, f.Title)
		detectedMap[key] = true
	}

	for _, f := range detected {
		var findingID int64
		queryID := "SELECT id FROM findings WHERE target = ? AND title = ?"
		if s.dbType == "postgres" {
			queryID = "SELECT id FROM findings WHERE target = $1 AND title = $2"
		}
		err := s.db.QueryRow(queryID, f.Target, f.Title).Scan(&findingID)
		if err != nil {
			continue // Finding not saved in DB, skip
		}

		var assignmentID int64
		var status string
		queryAss := "SELECT id, status FROM finding_assignments WHERE finding_id = ?"
		if s.dbType == "postgres" {
			queryAss = "SELECT id, status FROM finding_assignments WHERE finding_id = $1"
		}
		err = s.db.QueryRow(queryAss, findingID).Scan(&assignmentID, &status)

		if err == sql.ErrNoRows {
			// Auto-assign to asset owners if found
			owners, errOwners := s.GetAssetOwners(f.Target)
			var activeOwnerID, activeTeamID *int64
			if errOwners == nil {
				for _, o := range owners {
					if o.EndTime == nil {
						activeOwnerID = o.OwnerID
						activeTeamID = o.TeamID
						break
					}
				}
			}
			_, _ = s.AssignFinding(findingID, activeTeamID, activeOwnerID, f.Severity)
		} else if err == nil {
			normalized := normalizeCTEMState(status)
			if normalized == "Verified" || normalized == "Remediated" {
				_ = s.UpdateAssignmentStatusWithComment(assignmentID, "Reopened", "Vulnerability re-detected by scanner", "system")
			}
		}
	}

	for _, target := range scannedTargets {
		queryActive := `
			SELECT fa.id, fa.finding_id, f.title
			FROM finding_assignments fa
			JOIN findings f ON fa.finding_id = f.id
			WHERE f.target = ? AND fa.status NOT IN ('Remediated', 'Verified', 'SLA Exception')
		`
		if s.dbType == "postgres" {
			queryActive = `
				SELECT fa.id, fa.finding_id, f.title
				FROM finding_assignments fa
				JOIN findings f ON fa.finding_id = f.id
				WHERE f.target = $1 AND fa.status NOT IN ('Remediated', 'Verified', 'SLA Exception')
			`
		}
		rows, err := s.db.Query(queryActive, target)
		if err != nil {
			continue
		}

		type actAss struct {
			id    int64
			title string
		}
		var activeAssignments []actAss
		for rows.Next() {
			var aa actAss
			var fid int64
			if err := rows.Scan(&aa.id, &fid, &aa.title); err == nil {
				activeAssignments = append(activeAssignments, aa)
			}
		}
		rows.Close()

		for _, aa := range activeAssignments {
			key := fmt.Sprintf("%s:%s", target, aa.title)
			if !detectedMap[key] {
				_ = s.AutoRemediateFinding(aa.id, "Vulnerability no longer detected by scanner", "system")
			}
		}
	}

	return nil
}

// AutoRemediateFinding transitions a finding assignment to "Remediated", executing intermediate transition states if needed.
func (s *Storage) AutoRemediateFinding(id int64, comment string, resolvedBy string) error {
	var oldStatus string
	var querySelect string
	if s.dbType == "postgres" {
		querySelect = "SELECT status FROM finding_assignments WHERE id = $1"
	} else {
		querySelect = "SELECT status FROM finding_assignments WHERE id = ?"
	}
	err := s.db.QueryRow(querySelect, id).Scan(&oldStatus)
	if err != nil {
		return err
	}

	normalizedOld := normalizeCTEMState(oldStatus)
	if normalizedOld != "Remediated" {
		if !isValidTransition(normalizedOld, "Remediated") {
			// Transition to Remediating first
			if err := s.UpdateAssignmentStatusWithComment(id, "Remediating", "Auto-transitioning to Remediating prior to auto-remediation", resolvedBy); err != nil {
				return err
			}
		}
		// Transition to Remediated
		return s.UpdateAssignmentStatusWithComment(id, "Remediated", comment, resolvedBy)
	}
	return nil
}
