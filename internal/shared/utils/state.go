// Package utils provides shared utility functions
package utils

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

// Snapshot represents the results of a single scan run.
type Snapshot struct {
	Timestamp time.Time     `json:"timestamp"`
	Targets   []string      `json:"targets"`
	Events    []recon.Event `json:"events"`
}

// Diff represents changes between two consecutive scans.
type Diff struct {
	NewTargets     []string      `json:"new_targets"`
	RemovedTargets []string      `json:"removed_targets"`
	NewEvents      []recon.Event `json:"new_events"`
	RemovedEvents  []recon.Event `json:"removed_events"`
	Timestamp      time.Time     `json:"timestamp"`
	PreviousTime   time.Time     `json:"previous_time"`
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
		scanID, err := s.db.StartScan(scope)
		if err != nil {
			slog.Warn("failed to start db scan", "error", err)
		} else {
			if err := s.db.SaveTargets(scanID, targets); err != nil {
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

			if err := s.db.SaveEvents(scanID, dbEvents); err != nil {
				return err
			}

			if err := s.db.FinishScan(scanID); err != nil {
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

	// Persist the diff
	data, err := json.MarshalIndent(diff, "", "  ")
	if err == nil {
		_ = os.WriteFile(s.diffPath(scope), data, 0600)
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
