package services

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/interfaces/workers"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

// Notifier defines an interface for sending alerts.
// Implementations should handle delivery to Discord, Slack, Telegram, etc.
type Notifier interface {
	// SendAlert sends a finding notification to configured channels
	SendAlert(ctx context.Context, finding utils.Finding) error
}

// ProgressReporter defines an interface for reporting pipeline progress.
// This is used for TUI updates and dashboard reporting.
type ProgressReporter interface {
	// ReportStage updates progress on the current scanning stage
	// stage: 0-4 representing different phases of reconnaissance
	// tools: number of tools currently active
	// targets: number of targets being processed
	// complete: whether the stage is finished
	ReportStage(stage int, tools int, targets int, complete bool)
}

// Config holds runtime parameters for the recon orchestrator.
// This configuration controls how the reconnaissance engine behaves,
// including tool selection, concurrency, rate limiting, and proxy rotation.
type Config struct {
	// ToolNames is a list of enabled reconnaissance tool names
	ToolNames []string

	// Threads controls the maximum number of concurrent operations
	Threads int

	// Verbose enables detailed logging of reconnaissance activities
	Verbose bool

	// RateLimit is the max requests/second across all tools. 0 = unlimited.
	// This is essential for respecting target infrastructure and APIs.
	RateLimit int

	// Proxies is a list of proxy URLs for rotating traffic through tools.
	// Useful for distributed scanning and rotating source IPs.
	Proxies []string

	// ProxyURL is a single proxy URL used for the ProxyFeeder (legacy support).
	ProxyURL string

	// APIKeys maps provider names to their API keys for enriched scanning.
	// Supported keys: "shodan", "censys", "zoomfie", "hunter", "virustotal"
	APIKeys map[string]string

	// WordlistsDir is the directory where curated SecLists are stored.
	WordlistsDir string

	// TmpResultsDir is where per-tool streaming event artifacts are appended.
	// If empty, streaming persistence is disabled.
	TmpResultsDir string

	// Reporter is an optional progress tracker (e.g., for TUI updates).
	Reporter ProgressReporter

	// Notifier is an optional alert dispatcher.
	Notifier Notifier

	// Fleet holds Axiom distributed fleet configuration.
	Fleet FleetConfig

	// EventBus allows external configuration of the event bus (in-memory or distributed).
	EventBus queue.EventBus

	// Timeout is the max duration to wait for a job.
	Timeout time.Duration
}

// FleetConfig holds Axiom distributed fleet configuration.
// When enabled, reconnaissance can be distributed across multiple VPS instances,
// dramatically reducing scan time from hours to minutes.
type FleetConfig struct {
	// Enabled activates distributed scanning via Axiom
	Enabled bool

	// WorkerMesh enables distributing jobs via NATS instead of running locally or via Axiom
	WorkerMesh bool

	// FleetName is the name of the Axiom fleet to use
	FleetName string

	// FleetSize controls the number of instances in the fleet
	FleetSize int

	// DeleteAfter removes instances after scan completes (cost optimization)
	DeleteAfter bool

	// ProxyURL optional proxy for fleet communication
	ProxyURL string
}

// Orchestrator manages the staged execution of reconnaissance tools.
// It handles:
// - Tool initialization and validation
// - Concurrent execution with panic recovery
// - Rate limiting across all tools
// - Fleet distribution to Axiom
// - Real-time event streaming and notifications
// - Error handling and graceful degradation
type Orchestrator struct {
	// config holds all runtime configuration
	config Config

	// tools holds the enabled reconnaissance tool instances
	tools []Tool

	// limiter controls request rate across all tools
	limiter *network.Limiter

	// fleetRunner handles distributed scanning via Axiom
	fleetRunner *AxiomRunner

	// proxyFeeder manages proxy rotation
	proxyFeeder *ProxyFeeder

	// bus facilitates event distribution to listeners
	bus queue.EventBus
}

type eventReporter interface {
	ReportEvent(source, target string)
}

type toolStatusReporter interface {
	ReportToolStatus(tool, status, detail string)
}

type failureReporter interface {
	ReportFailure(tool, detail string)
}

// NewOrchestrator creates a new staged pipeline orchestrator with rate limiting.
func NewOrchestrator(config Config) *Orchestrator {
	tools := []Tool{}
	for _, name := range config.ToolNames {
		if tool, ok := GetToolByName(name); ok {
			tools = append(tools, tool)
			continue
		}
		slog.Warn("unknown tool skipped", "tool", strings.TrimSpace(name))
	}

	limiter := network.New(config.RateLimit)

	var fleetRunner *AxiomRunner
	if config.Fleet.Enabled {
		var err error
		fleetRunner, err = New(AxiomConfig{
			Enabled:     config.Fleet.Enabled,
			FleetName:   config.Fleet.FleetName,
			FleetSize:   config.Fleet.FleetSize,
			DeleteAfter: config.Fleet.DeleteAfter,
		})
		if err != nil {
			slog.Error("failed to initialize axiom fleet runner", "error", err)
		}
	}

	eventBus := config.EventBus
	if eventBus == nil {
		eventBus = queue.New() // Fallback to in-memory if not provided
	}

	if config.Fleet.WorkerMesh {
		hm := NewHealthMonitor(eventBus)
		hm.Start()
	}

	o := &Orchestrator{
		config:      config,
		tools:       tools,
		limiter:     limiter,
		fleetRunner: fleetRunner,
		bus:         eventBus,
	}

	if config.ProxyURL != "" {
		feeder, err := NewProxyFeeder(config.ProxyURL)
		if err != nil {
			slog.Error("failed to initialize proxy feeder", "error", err)
		} else {
			o.proxyFeeder = feeder
		}
	}

	return o
}

// Close releases resources held by the orchestrator (e.g., the rate limiter).
func (o *Orchestrator) Close() {
	if o.limiter != nil {
		o.limiter.Stop()
	}
	if o.fleetRunner != nil {
		o.fleetRunner.Close()
	}
}

// Run executes the full staged recon pipeline, cascading discovered targets forward.
func (o *Orchestrator) Run(ctx context.Context, initialTargets []string) ([]Event, error) {
	if len(o.tools) == 0 {
		return nil, errors.New("no recon tools configured")
	}

	ctx = WithAPIKeys(ctx, o.config.APIKeys)
	ctx = WithWordlistsDir(ctx, o.config.WordlistsDir)
	ctx = WithTmpResultsDir(ctx, o.config.TmpResultsDir)

	if err := o.ensureTmpResultsDir(); err != nil {
		slog.Warn("failed to initialize tmp results directory", "dir", o.config.TmpResultsDir, "error", err)
	}

	// Provision fleet if enabled
	if o.fleetRunner != nil {
		if err := o.fleetRunner.ProvisionFleet(ctx); err != nil {
			return nil, fmt.Errorf("fleet provisioning failed: %w", err)
		}
	}

	threads := o.config.Threads
	if threads < 1 {
		threads = 1
	}

	stages := make(map[int][]Tool)
	for _, tool := range o.tools {
		st := GetToolStage(tool.Name())
		stages[st] = append(stages[st], tool)
	}

	var allEvents []Event
	var allErrs []error
	currentTargets := initialTargets
	scopeGuard := normalize.NewScopeGuard(initialTargets)

	// Sequential stage execution order: preprocessing, passive, active probing, crawling, fuzzing, verification
	customOrder := []int{0, 1, 2, 3, 4, 5}
	for _, stageNum := range customOrder {
		stageTools := stages[stageNum]
		if len(stageTools) == 0 {
			continue
		}

		if len(currentTargets) == 0 {
			slog.Debug("stage skipped: no targets", "stage", stageNum)
			continue
		}

		slog.Info("starting pipeline stage",
			"stage", stageNum,
			"tools", len(stageTools),
			"targets", len(currentTargets),
			"fleet_mode", o.fleetRunner != nil,
		)
		if o.config.Reporter != nil {
			o.config.Reporter.ReportStage(stageNum, len(stageTools), len(currentTargets), false)
		}

		events, errs := o.runStage(ctx, stageTools, currentTargets, threads)
		events = filterEventsInScope(scopeGuard, events)
		allEvents = append(allEvents, events...)
		if len(errs) > 0 {
			allErrs = append(allErrs, errs...)
		}

		nextTargets := append(currentTargets, extractTargets(events)...)
		normalizedTargets := normalize.DeduplicateAndPreserveURLs(nextTargets)
		currentTargets = scopeGuard.Filter(normalizedTargets)

		// Use only live web URLs from httpx before web-heavy stages (crawling+).
		// This reduces noise and follows a "probe-then-enumerate-web" flow.
		if stageNum == 2 {
			liveWebTargets := extractLiveWebTargets(events)
			if len(liveWebTargets) > 0 {
				currentTargets = scopeGuard.Filter(normalize.DeduplicateAndPreserveURLs(liveWebTargets))
				slog.Info("gating downstream stages with live httpx targets", "live_targets", len(currentTargets))
			} else {
				slog.Warn("httpx produced no live web targets; keeping cascaded targets for downstream stages")
			}
		}
		if len(normalizedTargets) > len(currentTargets) {
			blocked := len(normalizedTargets) - len(currentTargets)
			slog.Warn("Scope Guard triggered! Blocked out-of-scope targets", "blocked_count", blocked, "stage", stageNum)
			o.reportFailure("scope-guard", fmt.Sprintf("blocked %d out-of-scope targets", blocked))
		}

		slog.Info("pipeline stage complete",
			"stage", stageNum,
			"events_found", len(events),
			"cascaded_targets", len(currentTargets),
		)
		if o.config.Reporter != nil {
			o.config.Reporter.ReportStage(stageNum, len(stageTools), len(currentTargets), true)
		}

		// Publish events to the internal bus for any reactive subscribers
		for _, ev := range events {
			o.bus.Publish(queue.Event{Target: ev.Target, Source: ev.Source, Type: ev.Type, Properties: ev.Properties})
		}

		// If proxy feeder is enabled, feed the discovered web targets to the proxy
		if o.proxyFeeder != nil && stageNum >= 3 {
			webURLs := []string{}
			for _, ev := range events {
				if strings.HasPrefix(ev.Target, "http") {
					webURLs = append(webURLs, ev.Target)
				}
			}
			if len(webURLs) > 0 {
				o.proxyFeeder.FeedURLs(ctx, webURLs, o.config.Threads)
			}
		}
	}

	if len(allErrs) > 0 {
		return allEvents, errors.Join(allErrs...)
	}
	return allEvents, nil
}

// Bus returns the internal event bus, allowing external modules to subscribe to reconnaissance events.
func (o *Orchestrator) Bus() queue.EventBus {
	return o.bus
}

func (o *Orchestrator) ensureTmpResultsDir() error {
	if strings.TrimSpace(o.config.TmpResultsDir) == "" {
		return nil
	}
	return os.MkdirAll(o.config.TmpResultsDir, 0700)
}

func (o *Orchestrator) runStage(ctx context.Context, tools []Tool, targets []string, threads int) ([]Event, []error) {
	type toolResult struct {
		tool   string
		events []Event
		err    error
	}

	results := make(chan toolResult, len(tools))

	// Determine how many tools to run concurrently and how many threads each gets.
	// We want to avoid spawning (num_tools * threads) concurrent processes.
	maxConcurrentTools := len(tools)
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

			// Rate limit before executing each tool (initial gate)
			if err := o.limiter.Wait(ctx); err != nil {
				results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s: rate limit cancelled: %w", tool.Name(), err)}
				return
			}
			o.reportToolStatus(tool.Name(), "running", fmt.Sprintf("%d targets", len(targets)))

			var events []Event
			var err error
			toolTargets := prepareTargetsForTool(tool.Name(), targets)

			if o.config.Fleet.WorkerMesh && o.bus != nil {
				capability := stageCapability(GetToolStage(tool.Name()))
				if capability != "" {
					slog.Debug("dispatching stage task via NATS worker mesh", "stage", GetToolStage(tool.Name()), "capability", capability, "targets", len(toolTargets))
					events, err = o.dispatchStageTaskToWorkerMesh(ctx, GetToolStage(tool.Name()), capability, toolTargets)
				} else {
					slog.Debug("executing tool via NATS worker mesh", "tool", tool.Name(), "targets", len(toolTargets))
					events, err = o.dispatchToWorkerMesh(ctx, tool.Name(), toolTargets, toolThreads)
				}
			} else if o.fleetRunner != nil {
				slog.Debug("executing tool via axiom fleet", "tool", tool.Name(), "targets", len(toolTargets))
				lines, runErr := o.fleetRunner.RunTool(ctx, tool.Name(), toolTargets, nil)
				if runErr != nil {
					err = runErr
				} else {
					events = NewEventsFromLines(lines, tool.Name(), nil)
				}
			} else {
				slog.Debug("executing tool locally", "tool", tool.Name(), "targets", len(toolTargets), "threads", toolThreads)
				events, err = tool.Run(ctx, toolTargets, toolThreads)
			}

			if err != nil {
				o.reportFailure(tool.Name(), err.Error())
				results <- toolResult{tool: tool.Name(), err: fmt.Errorf("%s: %w", tool.Name(), err)}
				return
			}

			slog.Debug("tool complete", "tool", tool.Name(), "events", len(events))
			o.reportToolStatus(tool.Name(), "done", fmt.Sprintf("%d findings", len(events)))
			for _, ev := range events {
				o.reportEvent(ev.Source, ev.Target)
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
			continue
		}
		if err := o.appendStageEventsToTmp(result.tool, result.events); err != nil {
			errs = append(errs, err)
		}
		events = append(events, result.events...)
	}
	return events, errs
}

func (o *Orchestrator) appendStageEventsToTmp(tool string, events []Event) error {
	if strings.TrimSpace(o.config.TmpResultsDir) == "" || len(events) == 0 {
		return nil
	}

	if err := os.MkdirAll(o.config.TmpResultsDir, 0700); err != nil {
		return fmt.Errorf("failed to create tmp results dir %s: %w", o.config.TmpResultsDir, err)
	}

	safeTool := sanitizeFilePart(tool)
	ts := time.Now().UTC().Format(time.RFC3339Nano)

	for _, base := range tmpArtifactBases(tool) {
		jsonPath := filepath.Join(o.config.TmpResultsDir, fmt.Sprintf("%s.jsonl", base))
		csvPath := filepath.Join(o.config.TmpResultsDir, fmt.Sprintf("%s.csv", base))
		if err := appendEventsJSONL(jsonPath, safeTool, ts, events); err != nil {
			return err
		}
		if err := appendEventsCSV(csvPath, safeTool, ts, events); err != nil {
			return err
		}
	}
	return nil
}

func tmpArtifactBases(tool string) []string {
	canonical := sanitizeFilePart(tool)
	bases := []string{canonical}

	// Compatibility alias so users can look for crt.sh artifacts directly.
	if normalizeToolName(tool) == "crtsh" {
		bases = append(bases, "crt.sh")
	}
	return bases
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

	encoder := json.NewEncoder(file)
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
	return nil
}

func appendEventsCSV(path, tool, timestamp string, events []Event) error {
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

	writer := csv.NewWriter(file)
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
	return nil
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

func prepareTargetsForTool(toolName string, targets []string) []string {
	if normalizeToolName(toolName) == "uro" {
		// uro is URL-focused; keep only fully-qualified web URLs.
		urls := make([]string, 0, len(targets))
		for _, target := range targets {
			t := strings.TrimSpace(strings.ToLower(target))
			if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
				urls = append(urls, target)
			}
		}
		return normalize.DeduplicateAndPreserveURLs(urls)
	}

	switch GetToolStage(toolName) {
	case 0, 1:
		// Preprocessing + passive/DNS tools should receive host-like targets,
		// not deep URL paths.
		return normalize.DeduplicateAndNormalize(targets)
	default:
		return targets
	}
}

func (o *Orchestrator) reportEvent(source, target string) {
	if reporter, ok := o.config.Reporter.(eventReporter); ok {
		reporter.ReportEvent(source, target)
	}
}

func (o *Orchestrator) reportToolStatus(tool, status, detail string) {
	if reporter, ok := o.config.Reporter.(toolStatusReporter); ok {
		reporter.ReportToolStatus(tool, status, detail)
	}
}

func (o *Orchestrator) reportFailure(tool, detail string) {
	if reporter, ok := o.config.Reporter.(failureReporter); ok {
		reporter.ReportFailure(tool, detail)
	}
}

func (o *Orchestrator) dispatchToWorkerMesh(ctx context.Context, toolName string, targets []string, threads int) ([]Event, error) {
	jobID := fmt.Sprintf("job-%s-%d", toolName, time.Now().UnixNano())

	jobData, err := json.Marshal(map[string]interface{}{
		"id":        jobID,
		"tool_name": toolName,
		"targets":   targets,
		"threads":   threads,
	})
	if err != nil {
		return nil, err
	}

	o.bus.Publish(queue.Event{
		Target: "workers",
		Source: "orchestrator",
		Type:   "job.recon",
		Data:   jobData,
		Properties: map[string]string{
			"job_id":    jobID,
			"tool_name": toolName,
		},
	})

	// Wait for job.complete event and collect tool events
	sub := o.bus.Subscribe(toolName)
	completeSub := o.bus.Subscribe("job.complete")

	var events []Event
	timeout := o.config.Timeout
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	ticker := time.NewTicker(timeout)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		case <-ticker.C:
			return events, fmt.Errorf("timeout waiting for worker mesh job %s", jobID)
		case ev := <-sub:
			// Tool specific events (e.g., from Nuclei, HTTPX)
			events = append(events, Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			})
		case ev := <-completeSub:
			if ev.Properties["job_id"] == jobID {
				if ev.Properties["status"] == "success" {
					return events, nil
				}
				return events, fmt.Errorf("worker mesh job failed: %s", ev.Properties["error"])
			}
		}
	}
}

func stageCapability(stage int) workers.CapabilityType {
	switch stage {
	case 1:
		return workers.CapSubdomainEnum
	case 2:
		return workers.CapPortScan
	case 3:
		return workers.CapBrowserRecon
	case 4:
		return workers.CapJSDiff
	default:
		return ""
	}
}

func (o *Orchestrator) dispatchStageTaskToWorkerMesh(ctx context.Context, stage int, capability workers.CapabilityType, targets []string) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	completeSub := o.bus.Subscribe("task.complete")
	eventSub := o.bus.Subscribe("event.>")

	taskSession := fmt.Sprintf("stage-%d-%d", stage, time.Now().UnixNano())
	pending := len(targets)

	for _, target := range targets {
		taskID := fmt.Sprintf("stage-%d-%d", stage, time.Now().UnixNano())
		taskPayload, err := json.Marshal(workers.Task{
			ID:        taskID,
			Type:      capability,
			Target:    target,
			SessionID: taskSession,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal stage task: %w", err)
		}

		o.bus.Publish(queue.Event{
			Target: target,
			Source: "orchestrator",
			Type:   fmt.Sprintf("task.%s", capability),
			Data:   taskPayload,
			Properties: map[string]string{
				"task_id":    taskID,
				"task_type":  string(capability),
				"stage":      fmt.Sprintf("%d", stage),
				"session_id": taskSession,
			},
		})
	}

	var events []Event
	timeout := o.config.Timeout
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	ticker := time.NewTicker(timeout)
	defer ticker.Stop()

	for pending > 0 {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		case <-ticker.C:
			return events, fmt.Errorf("timeout waiting for stage %d completion", stage)
		case ev := <-eventSub:
			if ev.Properties["session_id"] != taskSession {
				continue
			}
			events = append(events, Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			})
		case ev := <-completeSub:
			if ev.Properties["session_id"] != taskSession {
				continue
			}
			pending--
		}
	}

	return events, nil
}
