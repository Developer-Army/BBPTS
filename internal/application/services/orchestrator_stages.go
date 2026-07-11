package services

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
)

func (o *Orchestrator) runStage(ctx context.Context, tools []Tool, targets []string, threads int) ([]Event, []error) {
	parentID := telemetry.GetSpanID(ctx)
	var spanID string
	ctx, spanID = telemetry.InternalTracer.StartSpan(ctx, "runStage", parentID)
	defer func() {
		telemetry.InternalTracer.EndSpan(spanID, map[string]interface{}{
			"tools_count":   len(tools),
			"targets_count": len(targets),
		})
	}()

	type toolResult struct {
		tool   string
		events []Event
		err    error
	}

	results := make(chan toolResult, len(tools))

	maxConcurrentTools := len(tools)
	if len(tools) > 0 {
		stageNum := GetToolStage(tools[0].Name())
		if stageNum >= 2 {
			maxConcurrentTools = 1
		}
	}
	if maxConcurrentTools > threads {
		maxConcurrentTools = threads
	}
	if maxConcurrentTools < 1 {
		maxConcurrentTools = 1
	}

	toolThreads := threads / maxConcurrentTools
	if toolThreads < 1 {
		toolThreads = 1
	}

	sem := make(chan struct{}, maxConcurrentTools)
	var wg sync.WaitGroup

	// Run interactsh first if present in stage tools so its OOB URL
	// is available to nuclei/dalfox via context.
	var interactshEvents []Event
	var remainingTools []Tool
	for _, tool := range tools {
		if tool.Name() == "interactsh" {
			interactshEvents = o.runInteractshFirst(ctx, tool, targets, threads, spanID)
			for _, ev := range interactshEvents {
				if ev.Type == "oob_session" && ev.Target != "" {
					ctx = recon.WithInteractshOOBURL(ctx, ev.Target)
					slog.Info("Interactsh OOB URL available for downstream tools", "url", ev.Target)
					break
				}
			}
		} else {
			remainingTools = append(remainingTools, tool)
		}
	}
	if len(interactshEvents) > 0 {
		if err := o.appendStageEventsToTmp("interactsh", interactshEvents); err != nil {
			slog.Warn("failed to persist interactsh events", "error", err)
		}
	}
	tools = remainingTools

	for _, tool := range tools {
		tool := tool
		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- toolResult{tool: tool.Name(), err: ctx.Err()}
				return
			}

			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s panicked: %v\n%s", tool.Name(), r, buf[:n])}
				}
			}()

			if err := o.limiter.Wait(ctx); err != nil {
				results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s: rate limit cancelled: %w", tool.Name(), err)}
				return
			}
			o.reportToolStatus(tool.Name(), "running", fmt.Sprintf("%d targets", len(targets)))
			slog.Info(fmt.Sprintf("Running tool on %d targets", len(targets)), "tool", tool.Name())

			var events []Event
			var err error
			toolTargets := prepareTargetsForTool(tool.Name(), targets, o.config.NucleiTargetCap)

			toolSpanName := fmt.Sprintf("Tool.%s", tool.Name())
			toolCtx, toolSpanID := telemetry.InternalTracer.StartSpan(ctx, toolSpanName, spanID)
			defer func() {
				telemetry.InternalTracer.EndSpan(toolSpanID, map[string]interface{}{
					"targets_count": len(toolTargets),
					"events_count":  len(events),
					"error":         fmt.Sprintf("%v", err),
				})
			}()

			switch {
			case o.config.Fleet.WorkerMesh && o.bus != nil:
				capability := stageCapability(GetToolStage(tool.Name()))
				if capability != "" {
					slog.Debug("dispatching stage task via NATS worker mesh", "stage", GetToolStage(tool.Name()), "capability", capability, "targets", len(toolTargets))
					events, err = o.dispatchStageTaskToWorkerMesh(toolCtx, GetToolStage(tool.Name()), capability, toolTargets)
				} else {
					slog.Debug("executing tool via NATS worker mesh", "tool", tool.Name(), "targets", len(toolTargets))
					events, err = o.dispatchToWorkerMesh(toolCtx, tool.Name(), toolTargets, toolThreads)
				}
			case o.fleetRunner != nil:
				slog.Debug("executing tool via axiom fleet", "tool", tool.Name(), "targets", len(toolTargets))
				lines, runErr := o.fleetRunner.RunTool(toolCtx, tool.Name(), toolTargets, nil)
				if runErr != nil {
					err = runErr
				} else {
					events = NewEventsFromLines(lines, tool.Name(), nil)
				}
			default:
				if o.cache != nil && !recon.DryRunFromCtx(toolCtx) {
					if entry, ok := o.cache.Get(tool.Name(), toolTargets, toolThreads); ok {
						slog.Debug("cache hit", "tool", tool.Name(), "events", len(entry.Events))
						o.reportToolStatus(tool.Name(), "done", fmt.Sprintf("%d findings (cached)", len(entry.Events)))
						for _, ev := range entry.Events {
							o.reportEvent(ev)
						}
						results <- toolResult{tool: tool.Name(), events: entry.Events}
						return
					}
				}

				slog.Debug("executing tool locally with retry/circuit-breaker", "tool", tool.Name(), "targets", len(toolTargets), "threads", toolThreads)
				cb := o.circuitBreakers.Get(tool.Name())
				cbErr := network.Execute(cb, func() error {
					var e error
					events, e = RunToolWithRetry(toolCtx, tool, o.BuildScanContext(toolCtx), toolTargets, toolThreads, ToolRetryConfig())
					return e
				})

				if cbErr != nil {
					err = cbErr
				} else if o.cache != nil && !recon.DryRunFromCtx(toolCtx) {
					if errPut := o.cache.Put(tool.Name(), toolTargets, toolThreads, events); errPut != nil {
						slog.Warn("failed to write to tool execution cache", "tool", tool.Name(), "error", errPut)
					}
				}
			}

			if err != nil {
				slog.Error("Tool execution failed", "tool", tool.Name(), "error", err)
				o.reportFailure(tool.Name(), err.Error())
				results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s: %w", tool.Name(), err)}
				return
			}

			slog.Info(fmt.Sprintf("Tool completed successfully with %d findings", len(events)), "tool", tool.Name())
			o.reportToolStatus(tool.Name(), "done", fmt.Sprintf("%d findings", len(events)))
			for _, ev := range events {
				o.reportEvent(ev)
			}
			if err := o.appendStageEventsToTmp(tool.Name(), events); err != nil {
				slog.Warn("failed to persist tool events incrementally", "tool", tool.Name(), "error", err)
			}
			results <- toolResult{tool: tool.Name(), events: events}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var events []Event
	var errs []error
	for result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
			if o.manifest != nil {
				o.manifest.ToolStatuses[result.tool] = "failed: " + result.err.Error()
			}
			failEvent := Event{
				Target: strings.Join(targets, ","),
				Source: result.tool,
				Type:   "error",
				Properties: map[string]string{
					"error": result.err.Error(),
				},
			}
			if err := o.appendStageEventsToTmp(result.tool, []Event{failEvent}); err != nil {
				slog.Warn("failed to persist tool failure event", "tool", result.tool, "error", err)
			}
			continue
		}
		if o.manifest != nil {
			o.manifest.ToolStatuses[result.tool] = fmt.Sprintf("ok: %d events", len(result.events))
		}
		events = append(events, result.events...)
	}
	return events, errs
}

func (o *Orchestrator) runInteractshFirst(ctx context.Context, tool Tool, targets []string, threads int, parentSpanID string) []Event {
	toolTargets := prepareTargetsForTool(tool.Name(), targets, o.config.NucleiTargetCap)
	if len(toolTargets) == 0 {
		toolTargets = targets
	}

	o.reportToolStatus(tool.Name(), "running", fmt.Sprintf("%d targets", len(toolTargets)))
	slog.Info("Running interactsh first for OOB URL", "targets", len(toolTargets))

	toolCtx, toolSpanID := telemetry.InternalTracer.StartSpan(ctx, "Tool."+tool.Name(), parentSpanID)
	events, err := RunToolWithRetry(toolCtx, tool, o.BuildScanContext(toolCtx), toolTargets, threads, ToolRetryConfig())

	telemetry.InternalTracer.EndSpan(toolSpanID, map[string]interface{}{
		"targets_count": len(toolTargets),
		"events_count":  len(events),
		"error":         fmt.Sprintf("%v", err),
	})

	if err != nil {
		slog.Error("interactsh first-run failed", "error", err)
		return nil
	}

	for _, ev := range events {
		o.reportEvent(ev)
	}
	slog.Info("interactsh first-run completed", "events", len(events))
	return events
}

func (o *Orchestrator) appendStageEventsToTmp(tool string, events []Event) error {
	if strings.TrimSpace(o.config.TmpResultsDir) == "" || len(events) == 0 {
		return nil
	}

	if err := os.MkdirAll(o.config.TmpResultsDir, 0700); err != nil {
		return fmt.Errorf("failed to create tmp results dir %s: %w", o.config.TmpResultsDir, err)
	}

	deduped := deduplicateEvents(events)

	safeTool := sanitizeFilePart(tool)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	for _, base := range tmpArtifactBases(tool) {
		jsonPath := filepath.Join(o.config.TmpResultsDir, fmt.Sprintf("%s.jsonl", base))
		csvPath := filepath.Join(o.config.TmpResultsDir, fmt.Sprintf("%s.csv", base))
		if err := appendEventsJSONL(jsonPath, safeTool, ts, deduped); err != nil {
			return err
		}
		if err := appendEventsCSV(csvPath, safeTool, ts, deduped); err != nil {
			return err
		}
	}
	return nil
}

func deduplicateEvents(events []Event) []Event {
	seen := make(map[string]struct{}, len(events))
	out := make([]Event, 0, len(events))
	for _, ev := range events {
		vulnName := ""
		if ev.Properties != nil {
			vulnName = ev.Properties["vuln_name"]
		}
		key := ev.Source + "|" + ev.Target + "|" + ev.Type + "|" + vulnName
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ev)
	}
	return out
}

func tmpArtifactBases(tool string) []string {
	canonical := sanitizeFilePart(tool)
	return []string{canonical}
}

func sanitizeFilePart(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" {
		return "unknown_tool"
	}

	var b strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('_')
	}

	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "unknown_tool"
	}
	return out
}

func appendEventsJSONL(path, tool, timestamp string, events []Event) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open tmp JSON file %s: %w", path, err)
	}
	defer file.Close()

	bw := bufio.NewWriterSize(file, 64*1024)
	encoder := json.NewEncoder(bw)
	for _, ev := range events {
		record := struct {
			Timestamp  string            `json:"timestamp"`
			Tool       string            `json:"tool"`
			Target     string            `json:"target"`
			Source     string            `json:"source"`
			Type       string            `json:"type"`
			Properties map[string]string `json:"properties,omitempty"`
		}{
			Timestamp:  timestamp,
			Tool:       tool,
			Target:     ev.Target,
			Source:     ev.Source,
			Type:       ev.Type,
			Properties: ev.Properties,
		}
		if err := encoder.Encode(record); err != nil {
			return fmt.Errorf("failed to append JSON event to %s: %w", path, err)
		}
	}
	return bw.Flush()
}

var csvMu sync.Map

func appendEventsCSV(path, tool, timestamp string, events []Event) error {
	muI, _ := csvMu.LoadOrStore(path, &sync.Mutex{})
	mu := muI.(*sync.Mutex)
	mu.Lock()
	defer mu.Unlock()

	writeHeader := false
	if info, err := os.Stat(path); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to stat tmp CSV file %s: %w", path, err)
		}
		writeHeader = true
	} else if info.Size() == 0 {
		writeHeader = true
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open tmp CSV file %s: %w", path, err)
	}
	defer file.Close()

	bw := bufio.NewWriterSize(file, 64*1024)
	writer := csv.NewWriter(bw)
	if writeHeader {
		if err := writer.Write([]string{"timestamp", "tool", "target", "source", "type", "properties_json"}); err != nil {
			return fmt.Errorf("failed to write CSV header to %s: %w", path, err)
		}
	}

	for _, ev := range events {
		propsJSON, err := json.Marshal(ev.Properties)
		if err != nil {
			return fmt.Errorf("failed to serialize properties for CSV: %w", err)
		}
		if err := writer.Write([]string{timestamp, tool, ev.Target, ev.Source, ev.Type, string(propsJSON)}); err != nil {
			return fmt.Errorf("failed to append CSV event to %s: %w", path, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("failed to flush CSV file %s: %w", path, err)
	}
	return bw.Flush()
}

func extractTargets(events []Event) []string {
	targets := make([]string, 0, len(events))
	for _, event := range events {
		if strings.TrimSpace(event.Target) == "" {
			continue
		}
		targets = append(targets, event.Target)
	}
	return targets
}

func filterEventsInScope(scopeGuard *normalize.ScopeGuard, events []Event) []Event {
	if scopeGuard == nil || len(events) == 0 {
		return events
	}
	out := make([]Event, 0, len(events))
	for _, event := range events {
		if !scopeGuard.IsAllowed(event.Target) {
			continue
		}
		out = append(out, event)
	}
	return out
}

func extractLiveWebTargets(events []Event) []string {
	targets := make([]string, 0, len(events))
	for _, event := range events {
		if normalizeToolName(event.Source) != "httpx" {
			continue
		}
		target := strings.TrimSpace(event.Target)
		if !strings.HasPrefix(strings.ToLower(target), "http://") && !strings.HasPrefix(strings.ToLower(target), "https://") {
			continue
		}
		targets = append(targets, target)
	}
	return targets
}

func prepareTargetsForTool(toolName string, targets []string, nucleiTargetCap int) []string {
	name := normalizeToolName(toolName)
	if name == "uro" {
		urls := make([]string, 0, len(targets))
		for _, target := range targets {
			t := strings.TrimSpace(strings.ToLower(target))
			if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
				urls = append(urls, target)
			}
		}
		return normalize.DeduplicateAndPreserveURLs(urls)
	}

	stage := GetToolStage(toolName)
	if stage <= 1 || name == "dnsx" || name == "naabu" || name == "shodan" {
		return normalize.DeduplicateAndNormalize(targets)
	}

	if name == "ffuf" || name == "gobuster" || name == "feroxbuster" {
		var dirTargets []string
		seenDirs := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			parsed, err := url.Parse(target)
			if err != nil || parsed.Host == "" {
				continue
			}
			baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
			if _, ok := seenDirs[baseURL]; !ok {
				seenDirs[baseURL] = struct{}{}
				dirTargets = append(dirTargets, baseURL)
			}
			path := parsed.Path
			if path != "" && path != "/" {
				parts := strings.Split(path, "/")
				if len(parts) > 1 && parts[1] != "" {
					firstSeg := parts[1]
					if !strings.Contains(firstSeg, ".") {
						dirURL := fmt.Sprintf("%s://%s/%s", parsed.Scheme, parsed.Host, firstSeg)
						if _, ok := seenDirs[dirURL]; !ok {
							seenDirs[dirURL] = struct{}{}
							dirTargets = append(dirTargets, dirURL)
						}
					}
				}
			}
		}
		if len(dirTargets) > 10 {
			dirTargets = dirTargets[:10]
		}
		return dirTargets
	}

	if name == "dalfox" {
		var dalfoxTargets []string
		seen := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			if !strings.Contains(target, "?") {
				continue
			}
			if _, ok := seen[target]; !ok {
				seen[target] = struct{}{}
				dalfoxTargets = append(dalfoxTargets, target)
			}
		}
		if len(dalfoxTargets) == 0 {
			for _, target := range targets {
				if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
					continue
				}
				parsed, err := url.Parse(target)
				if err == nil && parsed.Host != "" {
					baseURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
					if _, ok := seen[baseURL]; !ok {
						seen[baseURL] = struct{}{}
						dalfoxTargets = append(dalfoxTargets, baseURL)
					}
				}
			}
		}
		if len(dalfoxTargets) > 20 {
			dalfoxTargets = dalfoxTargets[:20]
		}
		return dalfoxTargets
	}

	if name == "arjun" {
		var arjunTargets []string
		seen := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			if _, ok := seen[target]; !ok {
				seen[target] = struct{}{}
				arjunTargets = append(arjunTargets, target)
			}
		}
		if len(arjunTargets) > 50 {
			arjunTargets = arjunTargets[:50]
		}
		return arjunTargets
	}

	if name == "nuclei" {
		var nucleiTargets []string
		seen := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			tLower := strings.ToLower(target)
			if strings.HasSuffix(tLower, ".png") || strings.HasSuffix(tLower, ".jpg") ||
				strings.HasSuffix(tLower, ".jpeg") || strings.HasSuffix(tLower, ".gif") ||
				strings.HasSuffix(tLower, ".css") || strings.HasSuffix(tLower, ".ico") ||
				strings.HasSuffix(tLower, ".woff") || strings.HasSuffix(tLower, ".woff2") ||
				strings.HasSuffix(tLower, ".ttf") || strings.HasSuffix(tLower, ".svg") ||
				strings.HasSuffix(tLower, ".map") {
				continue
			}
			if _, ok := seen[target]; !ok {
				seen[target] = struct{}{}
				nucleiTargets = append(nucleiTargets, target)
			}
		}
		priorityScore := func(t string) int {
			t = strings.ToLower(t)
			score := 0
			keywords := []string{"admin", "api", "upload", "debug", "login", "config", "console", "setup", "vulnerable", "vuln"}
			for _, kw := range keywords {
				if strings.Contains(t, kw) {
					score += 10
				}
			}
			if strings.Contains(t, "?") {
				score += 5
			}
			score += strings.Count(t, "/")
			return score
		}
		sort.SliceStable(nucleiTargets, func(i, j int) bool {
			return priorityScore(nucleiTargets[i]) > priorityScore(nucleiTargets[j])
		})
		if nucleiTargetCap <= 0 {
			nucleiTargetCap = 200
		}
		if len(nucleiTargets) > nucleiTargetCap {
			slog.Warn("nuclei targets exceeded cap; truncating to priority targets", "original_count", len(nucleiTargets), "cap", nucleiTargetCap)
			nucleiTargets = nucleiTargets[:nucleiTargetCap]
		}
		return nucleiTargets
	}

	if name == "open_redirect" || name == "ratelimit_bypass" || name == "idor_assist" {
		var urlTargets []string
		seen := make(map[string]struct{})
		for _, target := range targets {
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				continue
			}
			if _, ok := seen[target]; ok {
				continue
			}
			seen[target] = struct{}{}
			urlTargets = append(urlTargets, target)
		}
		if len(urlTargets) > 100 {
			urlTargets = urlTargets[:100]
		}
		return urlTargets
	}

	return targets
}
