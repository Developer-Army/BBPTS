package assets

import (
	"time"
)

// DriftEvent represents a detected change in asset inventory or metadata.
type DriftEvent struct {
	AssetID     string    `json:"asset_id"`
	ChangeType  string    `json:"change_type"` // e.g. "new_subdomain", "new_service", "port_change", "tech_change"
	OldValue    string    `json:"old_value"`
	NewValue    string    `json:"new_value"`
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
}

// DetectDrift compares old asset states with incoming states.
func DetectDrift(oldAsset, newAsset Asset) []DriftEvent {
	var events []DriftEvent

	if oldAsset.ID == "" {
		// Fresh asset discovery
		events = append(events, DriftEvent{
			AssetID:     newAsset.ID,
			ChangeType:  "new_asset",
			OldValue:    "",
			NewValue:    newAsset.Name,
			Timestamp:   time.Now().UTC(),
			Description: "New asset registered in ASM inventory: " + newAsset.Name,
		})
		return events
	}

	// Check for type change (e.g., subdomain to service, IP to domain)
	if oldAsset.Type != newAsset.Type {
		events = append(events, DriftEvent{
			AssetID:     newAsset.ID,
			ChangeType:  "type_change",
			OldValue:    oldAsset.Type,
			NewValue:    newAsset.Type,
			Timestamp:   time.Now().UTC(),
			Description: "Asset type drifted from " + oldAsset.Type + " to " + newAsset.Type,
		})
	}

	// Check status changes
	if oldAsset.Status != newAsset.Status {
		events = append(events, DriftEvent{
			AssetID:     newAsset.ID,
			ChangeType:  "status_drift",
			OldValue:    oldAsset.Status,
			NewValue:    newAsset.Status,
			Timestamp:   time.Now().UTC(),
			Description: "Asset status drifted from " + oldAsset.Status + " to " + newAsset.Status,
		})
	}

	// Check criticality modifications
	if oldAsset.Criticality != newAsset.Criticality {
		events = append(events, DriftEvent{
			AssetID:     newAsset.ID,
			ChangeType:  "criticality_drift",
			OldValue:    oldAsset.Criticality,
			NewValue:    newAsset.Criticality,
			Timestamp:   time.Now().UTC(),
			Description: "Asset criticality changed from " + oldAsset.Criticality + " to " + newAsset.Criticality,
		})
	}

	return events
}
