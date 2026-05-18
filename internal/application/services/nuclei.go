// Package services provides application services for reconnaissance
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// NucleiTool wraps projectdiscovery/nuclei for automated vulnerability scanning.
type NucleiTool struct {
	// Tags filters templates to run. If empty, runs with default templates.
	Tags []string

	// Severity filters for minimum severity level.
	Severity []string

	// TemplatePaths are additional template directories/files.
	TemplatePaths []string
}

// nucleiOutput represents a single Nuclei JSON result line.
type nucleiOutput struct {
	TemplateID       string     `json:"template-id"`
	Info             nucleiInfo `json:"info"`
	MatcherName      string     `json:"matcher-name"`
	Type             string     `json:"type"`
	Host             string     `json:"host"`
	Matched          string     `json:"matched-at"`
	IP               string     `json:"ip"`
	Timestamp        string     `json:"timestamp"`
	CURLCmd          string     `json:"curl-command"`
	ExtractedResults []string   `json:"extracted-results"`
}

// nucleiInfo holds template metadata from Nuclei output.
type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	Reference   []string `json:"reference"`
}

func (t *NucleiTool) Name() string {
	return "nuclei"
}

// Run executes Nuclei against the given targets with configured filters.
// Targets should be live HTTP endpoints (output of httpx / katana / etc).
func (t *NucleiTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := RateLimitFromCtx(ctx)

	bulkSize := threads
	if bulkSize > 10 {
		bulkSize = 10
	}

	args := []string{
		"-silent",
		"-jsonl",
		"-no-color",
		"-bulk-size", fmt.Sprintf("%d", bulkSize),
		"-concurrency", fmt.Sprintf("%d", threads),
		"-timeout", "10",
		"-retries", "1",
		"-no-httpx",
	}

	if rateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", rateLimit), "-rate-limit-duration", "1s")
	}

	lowResource := LowResourceFromCtx(ctx)
	if lowResource {
		args = append(args,
			"-headless-bulk-size", "1",
			"-passive",
			"-stats-interval", "30",
		)
	}

	// Apply severity filter
	if len(t.Severity) > 0 {
		args = append(args, "-severity", strings.Join(t.Severity, ","))
	} else {
		// Default: only medium and above to avoid noise
		args = append(args, "-severity", "medium,high,critical")
	}

	// Apply tag filters
	if len(t.Tags) > 0 {
		args = append(args, "-tags", strings.Join(t.Tags, ","))
	}

	// Additional template paths
	for _, tp := range t.TemplatePaths {
		args = append(args, "-t", tp)
	}

	// Pass targets via stdin
	args = append(args, "-list", "-")
	input := strings.Join(targets, "\n")

	lines, err := RunCommandWithInputLines(ctx, []byte(input), "nuclei", args...)
	if err != nil {
		return nil, fmt.Errorf("nuclei execution failed: %w", err)
	}

	events := []Event{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var out nucleiOutput
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			continue
		}

		props := map[string]string{
			"template_id": out.TemplateID,
			"severity":    out.Info.Severity,
			"vuln_name":   out.Info.Name,
			"type":        out.Type,
			"matched_at":  out.Matched,
			"ip":          out.IP,
		}

		if out.Info.Description != "" {
			props["description"] = out.Info.Description
		}
		if len(out.Info.Tags) > 0 {
			props["nuclei_tags"] = strings.Join(out.Info.Tags, ",")
		}
		if len(out.Info.Reference) > 0 {
			props["references"] = strings.Join(out.Info.Reference, " | ")
		}
		if out.CURLCmd != "" {
			props["curl_command"] = out.CURLCmd
		}
		if len(out.ExtractedResults) > 0 {
			props["extracted"] = strings.Join(out.ExtractedResults, " | ")
		}

		target := out.Matched
		if target == "" {
			target = out.Host
		}

		events = append(events, NewEvent(target, t.Name(), "vulnerability", props))
	}

	return events, nil
}
