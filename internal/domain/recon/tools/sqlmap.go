package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// SQLMapTool wraps sqlmap for automated SQL injection testing.
type SQLMapTool struct {
	// Level sets the risk level (1-5, default: 1)
	Level int
	// Risk sets the risk level (1-3, default: 1)
	Risk int
	// Batch enables batch mode for multiple targets
	Batch bool
}

// sqlmapOutput represents a single SQLMap JSON result line.
type sqlmapOutput struct {
	Target    string `json:"target"`
	Place     string `json:"place"`
	Parameter string `json:"parameter"`
	Payload   string `json:"payload"`
	Technique string `json:"technique"`
	Title     string `json:"title"`
	Type      string `json:"type"`
	Code      int    `json:"code"`
}

func (t *SQLMapTool) Name() string {
	return "sqlmap"
}

// Run executes SQLMap against the given targets with configured filters.
// Targets should be URLs with query parameters (output of katana/gau/uro).
func (t *SQLMapTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	if !scanCtx.ExploitSQLI {
		slog.Info("SQLMap skipped: enable -exploit-sqli to run conservative SQLi exploitation checks")
		return nil, nil
	}

	// Filter to HTTP targets with query parameters
	var sqlTargets []string
	for _, t := range targets {
		if strings.HasPrefix(strings.ToLower(t), "http://") || strings.HasPrefix(strings.ToLower(t), "https://") {
			if strings.Contains(t, "?") {
				sqlTargets = append(sqlTargets, t)
			}
		}
	}
	if len(sqlTargets) == 0 {
		slog.Info("SQLMap: no targets with query parameters found")
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, sqlTargets, func(ctx context.Context, target string) ([]recon.Event, error) {
		return t.testTarget(ctx, target), nil
	})
}

// testTarget runs SQLMap against a single target URL.
func (t *SQLMapTool) testTarget(ctx context.Context, target string) []recon.Event {
	var events []recon.Event

	level := t.Level
	if level < 1 {
		level = 1
	} else if level > 5 {
		level = 5
	}

	risk := t.Risk
	if risk < 1 {
		risk = 1
	} else if risk > 3 {
		risk = 3
	}

	args := []string{
		"--url=" + target,
		"--batch",
		"--level=" + fmt.Sprintf("%d", level),
		"--risk=" + fmt.Sprintf("%d", risk),
		"--random-agent",
		"--timeout=10",
		"--retries=1",
		"--threads=1",
		"--output-dir=/tmp/sqlmap",
		"--json-output",
	}

	// Use a shorter timeout for SQLMap to avoid hanging
	shortCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	lines, err := RunCommandLines(shortCtx, "sqlmap", args...)
	if err != nil {
		slog.Debug("SQLMap execution failed", "target", target, "error", err)
		return nil
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var out sqlmapOutput
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			continue
		}

		// Only report confirmed SQL injection findings
		if out.Type == "sql_injection" || out.Title != "" {
			severity := "high"
			if strings.Contains(strings.ToLower(out.Title), "time-based") {
				severity = "medium"
			}

			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "SQL Injection",
				"severity":    severity,
				"parameter":   out.Parameter,
				"place":       out.Place,
				"payload":     out.Payload,
				"technique":   out.Technique,
				"description": out.Title,
			}, severity))
		}
	}

	return events
}

var _ recon.Tool = (*SQLMapTool)(nil)
