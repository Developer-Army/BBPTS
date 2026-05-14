package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// EvidenceBundle is a compact, triage-friendly export of the highest-value insights.
type EvidenceBundle struct {
	GeneratedISO string         `json:"generated_at"`
	Count        int            `json:"count"`
	Items        []EvidenceItem `json:"items"`
}

// EvidenceItem captures what to verify next for a host.
type EvidenceItem struct {
	Host           string   `json:"host"`
	DedupeKey      string   `json:"dedupe_key"`
	Score          int      `json:"score"`
	Confidence     int      `json:"confidence"`
	Priority       string   `json:"priority"`
	Sources        []string `json:"sources"`
	Tags           []string `json:"tags"`
	Reasons        []string `json:"reasons"`
	SuggestedTests []string `json:"suggested_tests"`
	EvidenceCount  int      `json:"evidence_count"`
}

// WriteEvidenceBundle writes the top N insights (by score, then confidence) as JSON.
func WriteEvidenceBundle(path string, insights []Insight, topN int) error {
	if topN <= 0 {
		topN = 25
	}
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
	}

	cp := make([]Insight, len(insights))
	copy(cp, insights)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].Score != cp[j].Score {
			return cp[i].Score > cp[j].Score
		}
		return cp[i].Confidence > cp[j].Confidence
	})
	if len(cp) > topN {
		cp = cp[:topN]
	}

	items := make([]EvidenceItem, 0, len(cp))
	for _, in := range cp {
		dk := in.DedupeKey
		if dk == "" {
			dk = in.Host
		}
		items = append(items, EvidenceItem{
			Host:           in.Host,
			DedupeKey:      dk,
			Score:          in.Score,
			Confidence:     in.Confidence,
			Priority:       in.Priority,
			Sources:        append([]string(nil), in.Sources...),
			Tags:           append([]string(nil), in.Tags...),
			Reasons:        append([]string(nil), in.Reasons...),
			SuggestedTests: append([]string(nil), in.SuggestedTests...),
			EvidenceCount:  in.EvidenceCount,
		})
	}

	bundle := EvidenceBundle{
		GeneratedISO: time.Now().UTC().Format(time.RFC3339),
		Count:        len(items),
		Items:        items,
	}

	data, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return fmt.Errorf("evidence bundle: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}
