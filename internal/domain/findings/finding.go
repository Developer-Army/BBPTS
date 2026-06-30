package findings

type Finding struct {
	ID            int64    `json:"id"`
	AssetID       string   `json:"asset_id"`
	RiskScore     int      `json:"risk_score"`
	Confidence    int      `json:"confidence"`
	EvidenceIDs   []string `json:"evidence_ids"`
	WorkflowState string   `json:"workflow_state"`
}
