package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type GowitnessTool struct{}

func (t *GowitnessTool) Name() string {
	return "gowitness"
}

func (t *GowitnessTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Filter HTTP targets
	var httpTargets []string
	for _, target := range targets {
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
			httpTargets = append(httpTargets, target)
		}
	}
	if len(httpTargets) == 0 {
		return nil, nil
	}

	// Create temp file for targets list
	tmpFile, err := os.CreateTemp("", "gowitness_targets_*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create gowitness temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	for _, target := range httpTargets {
		if _, err := tmpFile.WriteString(target + "\n"); err != nil {
			return nil, fmt.Errorf("failed to write to gowitness temp file: %w", err)
		}
	}

	// Ensure destination directory exists
	destDir := "results/screenshots"
	if tmpDir := GetTmpResultsDir(ctx); tmpDir != "" {
		destDir = filepath.Join(filepath.Dir(tmpDir), "screenshots")
	}
	_ = os.MkdirAll(destDir, 0755)

	args := []string{"file", "-f", tmpFile.Name(), "--destination", destDir, "--threads", fmt.Sprintf("%d", threads), "--write-db=false"}

	// Execute gowitness
	_, err = RunCommandLines(ctx, "gowitness", args...)
	if err != nil {
		return nil, fmt.Errorf("gowitness execution failed: %w", err)
	}

	events := make([]Event, 0, len(httpTargets))
	for _, target := range httpTargets {
		events = append(events, NewEvent(target, t.Name(), "screenshot", map[string]string{
			"screenshot_dir": destDir,
		}))
	}

	return events, nil
}
