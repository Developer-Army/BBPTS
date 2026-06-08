package assets

import "time"

// Asset represents a target asset in the ASM inventory.
type Asset struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Name        string    `json:"name"`
	Criticality string    `json:"criticality"`
	Environment string    `json:"environment"`
	OwnerID     *int64    `json:"owner_id"`
	Confidence  float64   `json:"confidence"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Status      string    `json:"status"`
}
