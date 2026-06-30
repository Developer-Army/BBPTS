package ownership

import (
	"errors"
	"fmt"
	"time"
)

type Owner struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	ManagerID *int64 `json:"manager_id,omitempty"`
}

type Team struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`
	ManagerID *int64 `json:"manager_id,omitempty"`
}

type BusinessUnit struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	DirectorID *int64 `json:"director_id,omitempty"`
}

type OwnershipAudit struct {
	Timestamp  time.Time `json:"timestamp"`
	Actor      string    `json:"actor"`
	Action     string    `json:"action"` // e.g., "Assign", "Escalate", "Revoke", "AdjustConfidence"
	PrevOwner  string    `json:"prev_owner"`
	NewOwner   string    `json:"new_owner"`
	Reason     string    `json:"reason"`
	Confidence float64   `json:"confidence"`
}

type AssetOwnership struct {
	AssetID        string           `json:"asset_id"`
	OwnerID        int64            `json:"owner_id,omitempty"`
	TeamID         int64            `json:"team_id,omitempty"`
	Confidence     float64          `json:"confidence"` // 0.0 to 1.0 (confidence in assignment)
	EscalationPath []string         `json:"escalation_path"`
	AuditTrail     []OwnershipAudit `json:"audit_trail"`
}

func (ao *AssetOwnership) IsUnmanagedRisk() bool {
	return ao.OwnerID == 0 && ao.TeamID == 0
}

type FindingOwnership struct {
	FindingID      int64            `json:"finding_id"`
	OwnerID        int64            `json:"owner_id,omitempty"`
	TeamID         int64            `json:"team_id,omitempty"`
	Confidence     float64          `json:"confidence"`
	EscalationPath []string         `json:"escalation_path"`
	AuditTrail     []OwnershipAudit `json:"audit_trail"`
}

func (fo *FindingOwnership) IsUnmanagedRisk() bool {
	return fo.OwnerID == 0 && fo.TeamID == 0
}

func (ao *AssetOwnership) AssignAssetOwner(newOwnerID int64, teamID int64, confidence float64, escalationPath []string, actor string, reason string) error {
	if confidence < 0.0 || confidence > 1.0 {
		return errors.New("confidence must be between 0.0 and 1.0")
	}

	prev := fmt.Sprintf("owner:%d,team:%d", ao.OwnerID, ao.TeamID)
	next := fmt.Sprintf("owner:%d,team:%d", newOwnerID, teamID)

	audit := OwnershipAudit{
		Timestamp:  time.Now(),
		Actor:      actor,
		Action:     "Assign",
		PrevOwner:  prev,
		NewOwner:   next,
		Reason:     reason,
		Confidence: confidence,
	}

	ao.OwnerID = newOwnerID
	ao.TeamID = teamID
	ao.Confidence = confidence
	ao.EscalationPath = escalationPath
	ao.AuditTrail = append(ao.AuditTrail, audit)
	return nil
}

func (fo *FindingOwnership) AssignFindingOwner(newOwnerID int64, teamID int64, confidence float64, escalationPath []string, actor string, reason string) error {
	if confidence < 0.0 || confidence > 1.0 {
		return errors.New("confidence must be between 0.0 and 1.0")
	}

	prev := fmt.Sprintf("owner:%d,team:%d", fo.OwnerID, fo.TeamID)
	next := fmt.Sprintf("owner:%d,team:%d", newOwnerID, teamID)

	audit := OwnershipAudit{
		Timestamp:  time.Now(),
		Actor:      actor,
		Action:     "Assign",
		PrevOwner:  prev,
		NewOwner:   next,
		Reason:     reason,
		Confidence: confidence,
	}

	fo.OwnerID = newOwnerID
	fo.TeamID = teamID
	fo.Confidence = confidence
	fo.EscalationPath = escalationPath
	fo.AuditTrail = append(fo.AuditTrail, audit)
	return nil
}

func GenerateEscalationChain(ownerEmail string, teamName string, managerEmail string, directorEmail string) []string {
	var chain []string
	if ownerEmail != "" {
		chain = append(chain, ownerEmail)
	}
	if managerEmail != "" {
		chain = append(chain, fmt.Sprintf("Team:%s Manager:<%s>", teamName, managerEmail))
	}
	if directorEmail != "" {
		chain = append(chain, fmt.Sprintf("Director:<%s>", directorEmail))
	}
	return chain
}
