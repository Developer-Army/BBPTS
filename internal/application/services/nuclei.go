// Package services provides application services for reconnaissance
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
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
	Request          string     `json:"request"`
	Response         string     `json:"response"`
}

// nucleiInfo holds template metadata from Nuclei output.
type nucleiInfo struct {
	Name        string                 `json:"name"`
	Severity    string                 `json:"severity"`
	Description string                 `json:"description"`
	Tags        []string               `json:"tags"`
	Reference   []string               `json:"reference"`
	Metadata    map[string]interface{} `json:"metadata"`
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

	if AutoUpdateFromCtx(ctx) {
		store := storage.FromContext(ctx)
		shouldUpdate := true
		if store != nil {
			if lastStr, err := store.GetSetting("lastTemplateUpdate"); err == nil && lastStr != "" {
				if lastTime, err := time.Parse(time.RFC3339, lastStr); err == nil {
					if time.Since(lastTime) < 24*time.Hour {
						shouldUpdate = false
						slog.Info("Nuclei template auto-update skipped: updated recently", "last_update", lastTime)
					}
				}
			}
		}
		if shouldUpdate {
			slog.Info("Auto-updating Nuclei templates...")
			_, err := RunCommandLines(ctx, "nuclei", "-update-templates")
			if err != nil {
				slog.Warn("Nuclei templates auto-update failed", "error", err)
			} else if store != nil {
				_ = store.SaveSetting("lastTemplateUpdate", time.Now().Format(time.RFC3339))
			}
		}
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())

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
		"-irr",
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

	// Wire interactsh OOB server for blind vulnerability detection
	if oobURL := InteractshOOBURLFromCtx(ctx); oobURL != "" {
		args = append(args, "-iserver", oobURL)
		slog.Info("Nuclei: using interactsh OOB server for blind detection", "iserver", oobURL)
	}

	// Apply severity filter
	if len(t.Severity) > 0 {
		args = append(args, "-severity", strings.Join(t.Severity, ","))
	} else {
		// Default: only medium and above to avoid noise
		args = append(args, "-severity", "medium,high,critical")
	}

	// Apply tag filters
	var finalTags []string
	finalTags = append(finalTags, t.Tags...)
	techTags := getTechTagsForTargets(ctx, targets)
	if len(techTags) > 0 {
		finalTags = append(finalTags, techTags...)
		slog.Info("Auto-selected Nuclei tags based on httpx technology fingerprint", "tags", techTags)
	}

	if len(finalTags) > 0 {
		args = append(args, "-tags", strings.Join(finalTags, ","))
	}

	// Additional template paths
	var finalTemplates []string
	finalTemplates = append(finalTemplates, t.TemplatePaths...)

	if len(techTags) > 0 {
		subsets := recon.ResolveTemplateSubsets(techTags)
		if len(subsets) > 0 {
			finalTemplates = append(finalTemplates, subsets...)
			slog.Info("Auto-selected Nuclei template subsets based on technology fingerprint", "subsets", subsets)
		}
		customTemplates := generateCustomNucleiTemplates(techTags)
		finalTemplates = append(finalTemplates, customTemplates...)
	}

	for _, tp := range finalTemplates {
		args = append(args, "-t", tp)
	}

	// Pass targets via stdin
	headers := HeadersFromCtx(ctx)
	for k, v := range headers {
		args = append(args, "-header", fmt.Sprintf("%s: %s", k, v))
	}
	for _, header := range wafBypassHeaders(WAFContextFromCtx(ctx)) {
		args = append(args, "-header", header)
	}

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
			"template_id":       out.TemplateID,
			"severity":          out.Info.Severity,
			"vuln_name":         out.Info.Name,
			"type":              out.Type,
			"matched_at":        out.Matched,
			"ip":                out.IP,
			"nuclei_severity":   out.Info.Severity,
		}

		if out.Request != "" {
			props["request"] = out.Request
		}
		if out.Response != "" {
			props["response"] = out.Response
		}

		if out.Info.Metadata != nil {
			if conf, ok := out.Info.Metadata["confidence"].(string); ok {
				props["nuclei_confidence"] = conf
			}
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

func generateCustomNucleiTemplates(techs []string) []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".config", "nuclei", "custom-templates")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil
	}

	var templates []string
	for _, tech := range techs {
		tech = strings.TrimSpace(strings.ToLower(tech))
		if tech == "" || len(recon.ResolveTemplateSubsets([]string{tech})) > 0 {
			continue
		}
		slug := regexp.MustCompile(`[^a-z0-9]+`).ReplaceAllString(tech, "-")
		slug = strings.Trim(slug, "-")
		if slug == "" {
			continue
		}
		path := filepath.Join(dir, "bbpts-"+slug+".yaml")
		content := fmt.Sprintf(`id: bbpts-%s-basic-exposure

info:
  name: BBPTS %s Basic Exposure Checks
  author: bbpts
  severity: info
  tags: bbpts,custom,%s,exposure

http:
  - method: GET
    path:
      - "{{BaseURL}}/version"
      - "{{BaseURL}}/debug"
      - "{{BaseURL}}/debug/vars"
      - "{{BaseURL}}/actuator/env"
      - "{{BaseURL}}/admin"
      - "{{BaseURL}}/login"

    matchers-condition: or
    matchers:
      - type: word
        part: body
        words:
          - "version"
          - "debug"
          - "default password"
          - "admin"
          - "%s"
`, slug, strings.Title(tech), slug, tech)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			continue
		}
		templates = append(templates, path)
	}
	return templates
}

func getTechTagsForTargets(ctx context.Context, targets []string) []string {
	store := storage.FromContext(ctx)
	if store == nil {
		return nil
	}

	techMap := make(map[string]bool)
	for _, target := range targets {
		candidates := []string{target}
		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			candidates = append(candidates, "https://"+target, "http://"+target)
		}

		for _, cand := range candidates {
			if evs, err := store.GetEventsByTarget(cand); err == nil {
				for _, ev := range evs {
					if ev.Source == "httpx" {
						if techStr, ok := ev.Properties["technologies"]; ok && techStr != "" {
							parts := strings.Split(techStr, ",")
							for _, part := range parts {
								tech := strings.TrimSpace(strings.ToLower(part))
								if tech != "" {
									techMap[tech] = true
								}
							}
						}
					}
				}
			}
		}
	}

	var techTags []string
	for tech := range techMap {
		techTags = append(techTags, tech)
	}
	return techTags
}
