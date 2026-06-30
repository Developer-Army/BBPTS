package findings

import "time"

type Evidence struct {
	ID          string    `json:"id"`
	AssetID     string    `json:"asset_id"`
	Source      string    `json:"source"`
	Confidence  float64   `json:"confidence"`
	CollectedAt time.Time `json:"collected_at"`
	RawData     []byte    `json:"raw_data"`
	Hash        string    `json:"hash"`
}
