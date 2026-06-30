// Package services provides application services for reconnaissance
package services

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
	"github.com/Developer-Army/BBPTS/internal/domain/security"
	_ "modernc.org/sqlite"
)

type AxiomConfig struct {
	// Enabled switches from local execution to Axiom fleet mode.
	Enabled bool `json:"enabled"`

	// FleetName is the name of your Axiom fleet to use (e.g., "bbpts-fleet").
	FleetName string `json:"fleet_name"`

	// FleetSize is the number of instances to spin up for scanning.
	FleetSize int `json:"fleet_size"`

	// DeleteAfter controls whether fleet instances are destroyed after scanning.
	DeleteAfter bool `json:"delete_after"`
}

func DefaultAxiomConfig() AxiomConfig {
	return AxiomConfig{
		Enabled:     false,
		FleetName:   "bbpts-fleet",
		FleetSize:   10,
		DeleteAfter: true,
	}
}

type AxiomRunner struct {
	cfg       AxiomConfig
	tempDir   string
	sanitizer *security.Sanitizer
}

func New(cfg AxiomConfig) (*AxiomRunner, error) {

	if _, err := exec.LookPath("axiom-scan"); err != nil {
		return nil, fmt.Errorf("axiom-scan not found in PATH: install from https://github.com/pry0cc/axiom")
	}

	sanitizer := security.NewSanitizer()
	if cfg.Enabled {
		if err := sanitizer.ValidateFleetName(cfg.FleetName); err != nil {
			return nil, fmt.Errorf("invalid fleet name: %w", err)
		}
		if err := sanitizer.ValidateInteger(cfg.FleetSize, 1, 1000); err != nil {
			return nil, fmt.Errorf("invalid fleet size: %w", err)
		}
	}

	tmp, err := os.MkdirTemp("", "bbpts-fleet-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	return &AxiomRunner{cfg: cfg, tempDir: tmp, sanitizer: sanitizer}, nil
}

func (r *AxiomRunner) Close() {
	os.RemoveAll(r.tempDir)
	if r.cfg.DeleteAfter && r.cfg.Enabled {
		slog.Info("fleet cleanup: destroying instances", "fleet", r.cfg.FleetName)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := tools.PrepareCommand(ctx, "axiom-fleet", "rm", r.cfg.FleetName, "--force")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("failed to destroy fleet", "error", err, "output", string(out))
		}
	}
}

func (r *AxiomRunner) ProvisionFleet(ctx context.Context) error {
	slog.Info("provisioning axiom fleet",
		"fleet", r.cfg.FleetName,
		"size", r.cfg.FleetSize,
	)
	cmd := tools.PrepareCommand(ctx, "axiom-fleet",
		r.cfg.FleetName,
		fmt.Sprintf("%d", r.cfg.FleetSize),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("axiom-fleet provisioning failed: %w\nOutput: %s", err, string(out))
	}
	slog.Info("axiom fleet provisioned", "fleet", r.cfg.FleetName)
	return nil
}

func (r *AxiomRunner) RunTool(ctx context.Context, toolName string, targets []string, extraArgs []string) ([]string, error) {

	if err := r.sanitizer.ValidateToolName(toolName); err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	if err := r.sanitizer.ValidateCommandArgs(extraArgs); err != nil {
		return nil, fmt.Errorf("invalid command arguments: %w", err)
	}

	inputFile := filepath.Join(r.tempDir, fmt.Sprintf("%s-input-%d.txt", toolName, time.Now().UnixNano()))
	outputFile := filepath.Join(r.tempDir, fmt.Sprintf("%s-output-%d.txt", toolName, time.Now().UnixNano()))

	if err := r.sanitizer.ValidateFilePath(inputFile); err != nil {
		return nil, fmt.Errorf("invalid input file path: %w", err)
	}
	if err := r.sanitizer.ValidateFilePath(outputFile); err != nil {
		return nil, fmt.Errorf("invalid output file path: %w", err)
	}

	if err := os.WriteFile(inputFile, []byte(strings.Join(targets, "\n")), 0600); err != nil {
		return nil, fmt.Errorf("failed to write targets file: %w", err)
	}
	defer os.Remove(inputFile)
	defer os.Remove(outputFile)

	module := toolName

	mapping := map[string]string{
		"puredns": "dnsx",
		"gau":     "gauplus",
	}
	if m, ok := mapping[toolName]; ok {
		module = m
	}

	args := []string{inputFile, "-m", module}
	args = append(args, extraArgs...)
	args = append(args, "-o", outputFile)
	if r.cfg.FleetName != "" {
		args = append(args, "--fleet", r.cfg.FleetName)
	}

	slog.Info("executing axiom-scan",
		"tool", toolName,
		"targets", len(targets),
		"fleet", r.cfg.FleetName,
	)

	cmd := tools.PrepareCommand(ctx, "axiom-scan", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("axiom-scan failed for %s: %w\nOutput: %s", toolName, err, string(out))
	}

	file, err := os.Open(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to open axiom output: %w", err)
	}
	defer file.Close()

	seen := make(map[string]struct{})
	var results []string

	scanner := bufio.NewScanner(file)

	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		results = append(results, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading axiom output stream: %w", err)
	}

	slog.Info("axiom-scan complete",
		"tool", toolName,
		"results", len(results),
	)

	return results, nil
}

type StatusReport struct {
	Instances []InstanceStatus `json:"instances"`
}

type InstanceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	IP     string `json:"ip"`
}

func (r *AxiomRunner) Status(ctx context.Context) (*StatusReport, error) {
	cmd := tools.PrepareCommand(ctx, "axiom-ls", "--json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query axiom status: %w", err)
	}

	var report StatusReport
	if err := json.Unmarshal(out, &report.Instances); err != nil {

		slog.Warn("could not parse axiom-ls JSON output", "error", err)
		return &StatusReport{}, nil
	}
	return &report, nil
}

func ImportAndMergeDatabase(masterDBPath, incomingDBPath string) error {

	masterDB, err := sql.Open("sqlite", masterDBPath)
	if err != nil {
		return fmt.Errorf("failed to open master database: %w", err)
	}
	defer masterDB.Close()

	incomingDB, err := sql.Open("sqlite", incomingDBPath)
	if err != nil {
		return fmt.Errorf("failed to open incoming database: %w", err)
	}
	defer incomingDB.Close()

	tx, err := masterDB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction on master database: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	scanRows, err := incomingDB.Query("SELECT id, scope, start_time, end_time, status FROM scans")
	if err != nil {

		return fmt.Errorf("failed to query scans from incoming database: %w", err)
	}
	defer scanRows.Close()

	type scanRecord struct {
		id        int64
		scope     string
		startTime string
		endTime   sql.NullString
		status    string
	}
	var scans []scanRecord
	for scanRows.Next() {
		var s scanRecord
		if err := scanRows.Scan(&s.id, &s.scope, &s.startTime, &s.endTime, &s.status); err != nil {
			return fmt.Errorf("failed to scan scan row: %w", err)
		}
		scans = append(scans, s)
	}
	scanRows.Close()

	scanIDMap := make(map[int64]int64)

	for _, s := range scans {
		// Check if a scan with the same scope, start_time already exists in master
		var existingID int64
		err := tx.QueryRow("SELECT id FROM scans WHERE scope = ? AND start_time = ?", s.scope, s.startTime).Scan(&existingID)
		if err == nil {

			scanIDMap[s.id] = existingID
			continue
		} else if err != sql.ErrNoRows {
			return fmt.Errorf("failed to check existing scan in master: %w", err)
		}

		res, err := tx.Exec("INSERT INTO scans (scope, start_time, end_time, status) VALUES (?, ?, ?, ?)",
			s.scope, s.startTime, s.endTime, s.status)
		if err != nil {
			return fmt.Errorf("failed to insert scan into master: %w", err)
		}
		newID, err := res.LastInsertId()
		if err != nil {
			return fmt.Errorf("failed to get last insert id: %w", err)
		}
		scanIDMap[s.id] = newID
	}

	targetRows, err := incomingDB.Query("SELECT scan_id, host, is_new FROM targets")
	if err == nil {
		defer targetRows.Close()
		for targetRows.Next() {
			var scanID int64
			var host string
			var isNew sql.NullBool
			if err := targetRows.Scan(&scanID, &host, &isNew); err != nil {
				return fmt.Errorf("failed to scan target row: %w", err)
			}
			newScanID, ok := scanIDMap[scanID]
			if !ok {
				continue
			}

			_, err = tx.Exec("INSERT OR IGNORE INTO targets (scan_id, host, is_new) VALUES (?, ?, ?)",
				newScanID, host, isNew)
			if err != nil {
				return fmt.Errorf("failed to insert target into master: %w", err)
			}
		}
	}

	eventRows, err := incomingDB.Query("SELECT scan_id, target, source, type, properties FROM events")
	if err == nil {
		defer eventRows.Close()
		for eventRows.Next() {
			var scanID int64
			var target, source, eventType, properties string
			if err := eventRows.Scan(&scanID, &target, &source, &eventType, &properties); err != nil {
				return fmt.Errorf("failed to scan event row: %w", err)
			}
			newScanID, ok := scanIDMap[scanID]
			if !ok {
				continue
			}

			_, err = tx.Exec("INSERT OR IGNORE INTO events (scan_id, target, source, type, properties) VALUES (?, ?, ?, ?, ?)",
				newScanID, target, source, eventType, properties)
			if err != nil {
				return fmt.Errorf("failed to insert event into master: %w", err)
			}
		}
	}

	insightRows, err := incomingDB.Query("SELECT scan_id, host, priority, score, tags FROM insights")
	if err == nil {
		defer insightRows.Close()
		for insightRows.Next() {
			var scanID int64
			var host string
			var priority sql.NullString
			var score sql.NullInt64
			var tags sql.NullString
			if err := insightRows.Scan(&scanID, &host, &priority, &score, &tags); err != nil {
				return fmt.Errorf("failed to scan insight row: %w", err)
			}
			newScanID, ok := scanIDMap[scanID]
			if !ok {
				continue
			}

			_, err = tx.Exec("INSERT OR REPLACE INTO insights (scan_id, host, priority, score, tags) VALUES (?, ?, ?, ?, ?)",
				newScanID, host, priority, score, tags)
			if err != nil {
				return fmt.Errorf("failed to insert/replace insight in master: %w", err)
			}
		}
	}

	return tx.Commit()
}
