// Package utils provides shared utility functions
package utils

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

// Snapshot represents the results of a single scan run.
type Snapshot struct {
	Timestamp time.Time     `json:"timestamp"`
	Targets   []string      `json:"targets"`
	Events    []recon.Event `json:"events"`
}

// RiskChange tracks risk score and severity changes for an asset.
type RiskChange struct {
	Host          string `json:"host"`
	PreviousScore int    `json:"previous_score"`
	CurrentScore  int    `json:"current_score"`
	PreviousSev   string `json:"previous_severity"`
	CurrentSev    string `json:"current_severity"`
}

// NewlyExposed tracks newly open ports or new vulnerability tags on an asset.
type NewlyExposed struct {
	Host        string   `json:"host"`
	ExposedItem string   `json:"exposed_item"`
	Why         []string `json:"why"`
}

// Diff represents changes between two consecutive scans.
type Diff struct {
	NewTargets     []string       `json:"new_targets"`
	RemovedTargets []string       `json:"removed_targets"`
	NewEvents      []recon.Event  `json:"new_events"`
	RemovedEvents  []recon.Event  `json:"removed_events"`
	RiskChanges    []RiskChange   `json:"risk_changes"`
	NewlyExposed   []NewlyExposed `json:"newly_exposed"`
	Timestamp      time.Time      `json:"timestamp"`
	PreviousTime   time.Time      `json:"previous_time"`
}

// Store manages persistent scan state on disk.
type Store struct {
	dir string
	db  *storage.DB
}

// NewStore creates a new state store. If useDB is true, it initializes a SQLite backend.
func NewStore(dir string, useDB bool) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create state directory: %w", err)
	}

	var db *storage.DB
	if useDB {
		dbPath := filepath.Join(dir, "bbpts.db")
		var err error
		db, err = storage.Open(dbPath)
		if err != nil {
			slog.Warn("failed to open database, falling back to JSON", "error", err)
		}
	}

	return &Store{dir: dir, db: db}, nil
}

// Close releases resources held by the store.
func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// GetDB returns the underlying SQLite database.
func (s *Store) GetDB() *storage.DB {
	return s.db
}

// snapshotPath returns the path for the latest snapshot for a given scope identifier.
func (s *Store) snapshotPath(scope string) string {
	return filepath.Join(s.dir, scope+"_latest.json")
}

// previousPath returns the path for the previous snapshot (before the latest).
func (s *Store) previousPath(scope string) string {
	return filepath.Join(s.dir, scope+"_previous.json")
}

// diffPath returns the path where the latest diff is stored.
func (s *Store) diffPath(scope string) string {
	return filepath.Join(s.dir, scope+"_diff.json")
}

// Save persists the current scan results. It rotates the previous snapshot
// before writing the new one, enabling subsequent diff computation.
func (s *Store) Save(scope string, targets []string, events []recon.Event) error {
	snap := Snapshot{
		Timestamp: time.Now().UTC(),
		Targets:   targets,
		Events:    events,
	}

	latestPath := s.snapshotPath(scope)
	prevPath := s.previousPath(scope)

	// Rotate: move current latest to previous
	if _, err := os.Stat(latestPath); err == nil {
		if err := os.Rename(latestPath, prevPath); err != nil {
			slog.Warn("failed to rotate state snapshot", "error", err)
		}
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal snapshot: %w", err)
	}

	if err := os.WriteFile(latestPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write snapshot: %w", err)
	}

	if s.db != nil {
		scanID, err := s.db.StartScan(context.Background(), scope)
		if err != nil {
			slog.Warn("failed to start db scan", "error", err)
		} else {
			if err := s.db.SaveTargets(context.Background(), scanID, targets); err != nil {
				return err
			}

			dbEvents := make([]storage.EventRecord, len(events))
			for i, ev := range events {
				dbEvents[i] = storage.EventRecord{
					Target:     ev.Target,
					Source:     ev.Source,
					Type:       ev.Type,
					Properties: ev.Properties,
				}
			}

			if err := s.db.SaveEvents(context.Background(), scanID, dbEvents); err != nil {
				return err
			}

			// Save insights for historical trend tracking
			currInsights := analyze.DeriveInsights(targets, events)
			dbInsights := make([]storage.InsightRecord, len(currInsights))
			for i, in := range currInsights {
				dbInsights[i] = storage.InsightRecord{
					Host:     in.Host,
					Priority: in.Priority,
					Score:    in.Score,
					Tags:     in.Tags,
				}
			}
			if err := s.db.SaveInsights(context.Background(), scanID, dbInsights); err != nil {
				return err
			}

			if err := s.db.FinishScan(context.Background(), scanID); err != nil {
				return err
			}
		}
	}

	slog.Info("scan state saved", "scope", scope, "events", len(events), "path", latestPath)
	return nil
}

// LoadLatest loads the most recent snapshot for a given scope.
func (s *Store) LoadLatest(scope string) (*Snapshot, error) {
	return s.loadSnapshot(s.snapshotPath(scope))
}

// LoadPrevious loads the previous snapshot for a given scope.
func (s *Store) LoadPrevious(scope string) (*Snapshot, error) {
	return s.loadSnapshot(s.previousPath(scope))
}

func (s *Store) loadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No previous state
		}
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %w", err)
	}
	return &snap, nil
}

// ComputeDiff compares the current scan results against the previous snapshot
// and returns a Diff showing new and removed targets/events.
func (s *Store) ComputeDiff(scope string, currentTargets []string, currentEvents []recon.Event) (*Diff, error) {
	prev, err := s.LoadPrevious(scope)
	if err != nil {
		return nil, err
	}

	if prev == nil {
		// First scan ever—everything is new
		return &Diff{
			NewTargets:     currentTargets,
			RemovedTargets: nil,
			NewEvents:      currentEvents,
			RemovedEvents:  nil,
			Timestamp:      time.Now().UTC(),
		}, nil
	}

	diff := &Diff{
		Timestamp:    time.Now().UTC(),
		PreviousTime: prev.Timestamp,
	}

	// Diff targets
	prevTargetSet := toSet(prev.Targets)
	currTargetSet := toSet(currentTargets)

	for _, t := range currentTargets {
		if _, ok := prevTargetSet[t]; !ok {
			diff.NewTargets = append(diff.NewTargets, t)
		}
	}
	for _, t := range prev.Targets {
		if _, ok := currTargetSet[t]; !ok {
			diff.RemovedTargets = append(diff.RemovedTargets, t)
		}
	}

	// Diff events by composite key (target+source)
	prevEventSet := eventKeySet(prev.Events)
	currEventSet := eventKeySet(currentEvents)

	for _, ev := range currentEvents {
		key := eventKey(ev)
		if _, ok := prevEventSet[key]; !ok {
			diff.NewEvents = append(diff.NewEvents, ev)
		}
	}
	for _, ev := range prev.Events {
		key := eventKey(ev)
		if _, ok := currEventSet[key]; !ok {
			diff.RemovedEvents = append(diff.RemovedEvents, ev)
		}
	}

	sort.Strings(diff.NewTargets)
	sort.Strings(diff.RemovedTargets)

	// Compute insights for both previous and current scans
	prevInsights := analyze.DeriveInsights(prev.Targets, prev.Events)
	currInsights := analyze.DeriveInsights(currentTargets, currentEvents)

	prevInsightMap := make(map[string]analyze.Insight)
	for _, in := range prevInsights {
		prevInsightMap[in.Host] = in
	}

	currInsightMap := make(map[string]analyze.Insight)
	for _, in := range currInsights {
		currInsightMap[in.Host] = in
	}

	// 1. Calculate Risk Changes (What got riskier)
	var riskChanges []RiskChange
	for host, currIn := range currInsightMap {
		if prevIn, ok := prevInsightMap[host]; ok {
			if currIn.Score > prevIn.Score {
				riskChanges = append(riskChanges, RiskChange{
					Host:          host,
					PreviousScore: prevIn.Score,
					CurrentScore:  currIn.Score,
					PreviousSev:   prevIn.Priority,
					CurrentSev:    currIn.Priority,
				})
			}
		}
	}
	diff.RiskChanges = riskChanges

	// 2. Calculate Newly Exposed
	var newlyExposed []NewlyExposed
	for host, currIn := range currInsightMap {
		prevIn, ok := prevInsightMap[host]
		if !ok {
			continue
		}

		prevTags := make(map[string]bool)
		for _, tag := range prevIn.Tags {
			prevTags[tag] = true
		}
		var newTags []string
		for _, tag := range currIn.Tags {
			if !prevTags[tag] {
				newTags = append(newTags, tag)
			}
		}

		prevEv := make(map[string]bool)
		for _, ev := range prevIn.Evidence {
			prevEv[ev] = true
		}
		var newEvs []string
		for _, ev := range currIn.Evidence {
			if !prevEv[ev] {
				newEvs = append(newEvs, ev)
			}
		}

		if len(newTags) > 0 || len(newEvs) > 0 {
			why := []string{}
			for _, tag := range newTags {
				why = append(why, fmt.Sprintf("New feature/vulnerability: %s", tag))
			}
			for _, ev := range newEvs {
				why = append(why, fmt.Sprintf("New exposed path/service: %s", ev))
			}
			newlyExposed = append(newlyExposed, NewlyExposed{
				Host:         host,
				ExposedItem:  "New vulnerabilities or endpoints detected",
				Why:          why,
			})
		}
	}
	diff.NewlyExposed = newlyExposed

	// Persist the diff
	data, err := json.MarshalIndent(diff, "", "  ")
	if err == nil {
		if errWrite := os.WriteFile(s.diffPath(scope), data, 0600); errWrite != nil {
			slog.Warn("failed to write diff file", "path", s.diffPath(scope), "error", errWrite)
		}
	}

	return diff, nil
}

func toSet(items []string) map[string]struct{} {
	s := make(map[string]struct{}, len(items))
	for _, item := range items {
		s[item] = struct{}{}
	}
	return s
}

func eventKey(ev recon.Event) string {
	// Deep Diffing: Hash the properties to detect parameter/schema changes
	var propStr string
	if len(ev.Properties) > 0 {
		keys := make([]string, 0, len(ev.Properties))
		for k := range ev.Properties {
			// Skip highly volatile/ephemeral fields
			if k == "timestamp" || k == "time" || k == "duration" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			propStr += k + ":" + ev.Properties[k] + ";"
		}
	}
	hash := sha256.Sum256([]byte(propStr))
	return fmt.Sprintf("%s|%s|%x", ev.Source, ev.Target, hash[:8])
}

func eventKeySet(events []recon.Event) map[string]struct{} {
	s := make(map[string]struct{}, len(events))
	for _, ev := range events {
		s[eventKey(ev)] = struct{}{}
	}
	return s
}

// ToMarkdown converts the diff results into markdown report.
func (d *Diff) ToMarkdown(scope string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Differential Reconnaissance Report - %s\n\n", scope))
	sb.WriteString(fmt.Sprintf("**Previous Scan:** %s\n\n", d.PreviousTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Current Scan:** %s\n\n", d.Timestamp.Format(time.RFC3339)))

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("- **New Targets:** %d\n", len(d.NewTargets)))
	sb.WriteString(fmt.Sprintf("- **Removed Targets:** %d\n", len(d.RemovedTargets)))
	sb.WriteString(fmt.Sprintf("- **New Events:** %d\n", len(d.NewEvents)))
	sb.WriteString(fmt.Sprintf("- **Removed Events:** %d\n", len(d.RemovedEvents)))
	sb.WriteString(fmt.Sprintf("- **Riskier Assets:** %d\n", len(d.RiskChanges)))
	sb.WriteString(fmt.Sprintf("- **Newly Exposed Assets:** %d\n\n", len(d.NewlyExposed)))

	if len(d.NewTargets) > 0 {
		sb.WriteString("## New Targets\n\n")
		for _, t := range d.NewTargets {
			sb.WriteString(fmt.Sprintf("- `%s`\n", t))
		}
		sb.WriteString("\n")
	}

	if len(d.NewEvents) > 0 {
		sb.WriteString("## New Events\n\n")
		for _, ev := range d.NewEvents {
			sb.WriteString(fmt.Sprintf("- **%s** `%s` (from %s)\n", ev.Type, ev.Target, ev.Source))
		}
		sb.WriteString("\n")
	}

	if len(d.RiskChanges) > 0 {
		sb.WriteString("## Riskier Assets\n\n")
		for _, rc := range d.RiskChanges {
			sb.WriteString(fmt.Sprintf("- **%s**: Score %d (%s) -> %d (%s)\n", rc.Host, rc.PreviousScore, rc.PreviousSev, rc.CurrentScore, rc.CurrentSev))
		}
		sb.WriteString("\n")
	}

	if len(d.NewlyExposed) > 0 {
		sb.WriteString("## Newly Exposed Assets\n\n")
		for _, ne := range d.NewlyExposed {
			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", ne.Host, ne.ExposedItem))
			for _, w := range ne.Why {
				sb.WriteString(fmt.Sprintf("  - %s\n", w))
			}
		}
		sb.WriteString("\n")
	}

	return sb.String()
}
