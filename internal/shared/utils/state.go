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

type Snapshot struct {
	Timestamp time.Time     `json:"timestamp"`
	Targets   []string      `json:"targets"`
	Events    []recon.Event `json:"events"`
}

type RiskChange struct {
	Host          string `json:"host"`
	PreviousScore int    `json:"previous_score"`
	CurrentScore  int    `json:"current_score"`
	PreviousSev   string `json:"previous_severity"`
	CurrentSev    string `json:"current_severity"`
}

type NewlyExposed struct {
	Host        string   `json:"host"`
	ExposedItem string   `json:"exposed_item"`
	Why         []string `json:"why"`
}

type Diff struct {
	NewTargets     []string          `json:"new_targets"`
	RemovedTargets []string          `json:"removed_targets"`
	NewEvents      []recon.Event     `json:"new_events"`
	RemovedEvents  []recon.Event     `json:"removed_events"`
	RiskChanges    []RiskChange      `json:"risk_changes"`
	NewlyExposed   []NewlyExposed    `json:"newly_exposed"`
	Timestamp      time.Time         `json:"timestamp"`
	PreviousTime   time.Time         `json:"previous_time"`
	ChangeReasons  map[string]string `json:"change_reasons,omitempty"`
}

type Store struct {
	dir string
	db  *storage.DB
}

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

func (s *Store) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

func (s *Store) GetDB() *storage.DB {
	return s.db
}

func (s *Store) snapshotPath(scope string) string {
	return filepath.Join(s.dir, scope+"_latest.json")
}

func (s *Store) previousPath(scope string) string {
	return filepath.Join(s.dir, scope+"_previous.json")
}

func (s *Store) diffPath(scope string) string {
	return filepath.Join(s.dir, scope+"_diff.json")
}

func (s *Store) Save(scope string, targets []string, events []recon.Event) error {
	snap := Snapshot{
		Timestamp: time.Now().UTC(),
		Targets:   targets,
		Events:    events,
	}

	latestPath := s.snapshotPath(scope)
	prevPath := s.previousPath(scope)

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

func (s *Store) LoadLatest(scope string) (*Snapshot, error) {
	return s.loadSnapshot(s.snapshotPath(scope))
}

func (s *Store) LoadPrevious(scope string) (*Snapshot, error) {
	return s.loadSnapshot(s.previousPath(scope))
}

func (s *Store) loadSnapshot(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read snapshot: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot: %w", err)
	}
	return &snap, nil
}

func (s *Store) ComputeDiff(scope string, currentTargets []string, currentEvents []recon.Event) (*Diff, error) {
	prev, err := s.LoadPrevious(scope)
	if err != nil {
		return nil, err
	}

	if prev == nil {

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
				Host:        host,
				ExposedItem: "New vulnerabilities or endpoints detected",
				Why:         why,
			})
		}
	}
	diff.NewlyExposed = newlyExposed

	diff.ChangeReasons = make(map[string]string)
	for _, t := range diff.NewTargets {
		reason := "Newly discovered target subdomain/host"
		for _, ev := range currentEvents {
			if ev.Target == t {
				switch ev.Type {
				case "port_open":
					reason = fmt.Sprintf("Newly discovered target with open port %s", ev.Properties["port"])
				case "service":
					reason = "Newly resolved active service target"
				}
			}
		}
		diff.ChangeReasons[t] = reason
	}

	for _, ev := range diff.NewEvents {
		key := eventKey(ev)
		reason := "New security/recon discovery"
		switch ev.Type {
		case "port_open":
			reason = fmt.Sprintf("Port %s became open/accessible", ev.Properties["port"])
		case "vulnerability":
			reason = fmt.Sprintf("New vulnerability detected: %s", ev.Properties["vuln_name"])
		case "secret_exposed":
			reason = "Exposed credential/secrets found"
		case "discovery":
			reason = "New interesting asset metadata discovered"
		}
		diff.ChangeReasons[key] = reason
	}

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
			reason := d.ChangeReasons[t]
			if reason == "" {
				reason = "Newly discovered target subdomain/host"
			}
			sb.WriteString(fmt.Sprintf("- `%s` (%s)\n", t, reason))
		}
		sb.WriteString("\n")
	}

	if len(d.NewEvents) > 0 {
		sb.WriteString("## New Events\n\n")
		for _, ev := range d.NewEvents {
			reason := d.ChangeReasons[eventKey(ev)]
			if reason == "" {
				reason = "New security/recon discovery"
			}
			sb.WriteString(fmt.Sprintf("- **%s** `%s` (from %s): %s\n", ev.Type, ev.Target, ev.Source, reason))
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
