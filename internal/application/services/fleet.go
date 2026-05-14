// Package services provides application services for reconnaissance
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/security"
)

// AxiomConfig holds the Axiom fleet configuration.
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

// DefaultAxiomConfig returns sensible defaults for fleet mode.
func DefaultAxiomConfig() AxiomConfig {
	return AxiomConfig{
		Enabled:     false,
		FleetName:   "bbpts-fleet",
		FleetSize:   10,
		DeleteAfter: true,
	}
}

// AxiomRunner wraps tool execution using `axiom-scan`.
type AxiomRunner struct {
	cfg       AxiomConfig
	tempDir   string
	sanitizer *security.Sanitizer
}

// New creates a new AxiomRunner.
func New(cfg AxiomConfig) (*AxiomRunner, error) {
	// Verify axiom is installed
	if _, err := exec.LookPath("axiom-scan"); err != nil {
		return nil, fmt.Errorf("axiom-scan not found in PATH: install from https://github.com/pry0cc/axiom")
	}

	// Validate configuration
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

// Close cleans up temporary files and optionally destroys the fleet.
func (r *AxiomRunner) Close() {
	os.RemoveAll(r.tempDir)
	if r.cfg.DeleteAfter && r.cfg.Enabled {
		slog.Info("fleet cleanup: destroying instances", "fleet", r.cfg.FleetName)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "axiom-fleet", "rm", r.cfg.FleetName, "--force")
		if out, err := cmd.CombinedOutput(); err != nil {
			slog.Warn("failed to destroy fleet", "error", err, "output", string(out))
		}
	}
}

// ProvisionFleet ensures the Axiom fleet is running.
func (r *AxiomRunner) ProvisionFleet(ctx context.Context) error {
	slog.Info("provisioning axiom fleet",
		"fleet", r.cfg.FleetName,
		"size", r.cfg.FleetSize,
	)
	cmd := exec.CommandContext(ctx, "axiom-fleet",
		r.cfg.FleetName,
		fmt.Sprintf("%d", r.cfg.FleetSize),
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("axiom-fleet provisioning failed: %w\nOutput: %s", err, string(out))
	}
	slog.Info("axiom fleet provisioned", "fleet", r.cfg.FleetName)
	return nil
}

// RunTool distributes a tool execution across the Axiom fleet.
// It writes targets to a temp file and uses axiom-scan to distribute the work.
func (r *AxiomRunner) RunTool(ctx context.Context, toolName string, targets []string, extraArgs []string) ([]string, error) {
	// Validate tool name
	if err := r.sanitizer.ValidateToolName(toolName); err != nil {
		return nil, fmt.Errorf("invalid tool name: %w", err)
	}

	// Validate extra arguments
	if err := r.sanitizer.ValidateCommandArgs(extraArgs); err != nil {
		return nil, fmt.Errorf("invalid command arguments: %w", err)
	}

	// Write targets to temp file (axiom-scan requires a file input)
	inputFile := filepath.Join(r.tempDir, fmt.Sprintf("%s-input-%d.txt", toolName, time.Now().UnixNano()))
	outputFile := filepath.Join(r.tempDir, fmt.Sprintf("%s-output-%d.txt", toolName, time.Now().UnixNano()))

	// Validate file paths
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

	// Construct axiom-scan command
	// Format: axiom-scan <input> -m <module> [args] -o <output>
	module := toolName
	// Map BBPTS tool names to Axiom module names if they differ
	mapping := map[string]string{
		"puredns": "dnsx", // or whatever module axiom uses for dns
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

	cmd := exec.CommandContext(ctx, "axiom-scan", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("axiom-scan failed for %s: %w\nOutput: %s", toolName, err, string(out))
	}

	// Read output file
	data, err := os.ReadFile(outputFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil // No results is OK
		}
		return nil, fmt.Errorf("failed to read axiom output: %w", err)
	}

	// Deduplicate results
	seen := make(map[string]struct{})
	var results []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		results = append(results, line)
	}

	slog.Info("axiom-scan complete",
		"tool", toolName,
		"results", len(results),
	)

	return results, nil
}

// StatusReport holds information about the current fleet state.
type StatusReport struct {
	Instances []InstanceStatus `json:"instances"`
}

// InstanceStatus holds per-instance state.
type InstanceStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	IP     string `json:"ip"`
}

// Status returns the current status of all fleet instances.
func (r *AxiomRunner) Status(ctx context.Context) (*StatusReport, error) {
	cmd := exec.CommandContext(ctx, "axiom-ls", "--json")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to query axiom status: %w", err)
	}

	var report StatusReport
	if err := json.Unmarshal(out, &report.Instances); err != nil {
		// axiom-ls output format may vary — return raw count
		slog.Warn("could not parse axiom-ls JSON output", "error", err)
		return &StatusReport{}, nil
	}
	return &report, nil
}
