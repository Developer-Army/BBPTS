package recon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/core/bus"
	"github.com/Developer-Army/BBPTS/internal/core/normalize"
	"github.com/Developer-Army/BBPTS/internal/core/notify"
	"github.com/Developer-Army/BBPTS/internal/core/ratelimit"
	"github.com/Developer-Army/BBPTS/internal/engine/fleet"
	"github.com/Developer-Army/BBPTS/internal/engine/integration"
)

type contextKey string

const wordlistsDirContextKey contextKey = "wordlistsDir"

// WithWordlistsDir injects the configured wordlists directory into tool context.
func WithWordlistsDir(ctx context.Context, dir string) context.Context {
	if strings.TrimSpace(dir) == "" {
		return ctx
	}
	return context.WithValue(ctx, wordlistsDirContextKey, dir)
}

func wordlistsDirFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	dir, _ := ctx.Value(wordlistsDirContextKey).(string)
	return dir
}

// GetWordlistPath returns the full path to a specific wordlist for a tool type.
func GetWordlistPath(ctx context.Context, wordlistType string) string {
	wordlistsDir := wordlistsDirFromContext(ctx)
	if wordlistsDir == "" {
		return ""
	}

	var wordlistName string
	switch wordlistType {
	case "dns":
		wordlistName = "dns-5k.txt"
	case "directory":
		wordlistName = "raft-small-files.txt"
	case "subdomain":
		wordlistName = "subdomains-top1million-5000.txt"
	case "api":
		wordlistName = "api-endpoints.txt"
	default:
		wordlistName = "common.txt"
	}

	return filepath.Join(wordlistsDir, wordlistName)
}

// Notifier defines an interface for sending alerts.
// Implementations should handle delivery to Discord, Slack, Telegram, etc.
type Notifier interface {
	// SendAlert sends a finding notification to configured channels
	SendAlert(ctx context.Context, finding notify.Finding) error
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

	// Reporter is an optional progress tracker (e.g., for TUI updates).
	Reporter ProgressReporter

	// Notifier is an optional alert dispatcher.
	Notifier Notifier

	// Fleet holds Axiom distributed fleet configuration.
	Fleet FleetConfig
}

// FleetConfig holds Axiom distributed fleet configuration.
// When enabled, reconnaissance can be distributed across multiple VPS instances,
// dramatically reducing scan time from hours to minutes.
type FleetConfig struct {
	// Enabled activates distributed scanning via Axiom
	Enabled bool

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
	limiter *ratelimit.Limiter

	// fleetRunner handles distributed scanning via Axiom
	fleetRunner *fleet.AxiomRunner

	// proxyFeeder manages proxy rotation
	proxyFeeder *integration.ProxyFeeder

	// bus facilitates event distribution to listeners
	bus *bus.Bus
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

	limiter := ratelimit.New(config.RateLimit)

	var fleetRunner *fleet.AxiomRunner
	if config.Fleet.Enabled {
		var err error
		fleetRunner, err = fleet.New(fleet.Config{
			Enabled:     config.Fleet.Enabled,
			FleetName:   config.Fleet.FleetName,
			FleetSize:   config.Fleet.FleetSize,
			DeleteAfter: config.Fleet.DeleteAfter,
		})
		if err != nil {
			slog.Error("failed to initialize axiom fleet runner", "error", err)
		}
	}

	o := &Orchestrator{
		config:      config,
		tools:       tools,
		limiter:     limiter,
		fleetRunner: fleetRunner,
		bus:         bus.New(),
	}

	if config.ProxyURL != "" {
		feeder, err := integration.NewProxyFeeder(config.ProxyURL)
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

func getToolStage(name string) int {
	switch normalizeToolName(name) {
	case "uro":
		return 0 // Preprocessing
	case "amass", "assetfinder", "crtsh", "subfinder", "chaos", "puredns":
		return 1 // Passive & DNS Recon
	case "dnsx", "naabu", "httpx":
		return 2 // Active Probing (Ports & Web)
	case "katana", "waybackurls", "gau", "hakrawler":
		return 3 // Crawling & URL Discovery
	case "ffuf", "gobuster", "feroxbuster":
		return 4 // Directory Fuzzing
	case "nuclei", "interactsh", "dalfox":
		return 5 // Vulnerability Verification
	default:
		return 3
	}
}

// Run executes the full staged recon pipeline, cascading discovered targets forward.
func (o *Orchestrator) Run(ctx context.Context, initialTargets []string) ([]Event, error) {
	if len(o.tools) == 0 {
		return nil, errors.New("no recon tools configured")
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
		st := getToolStage(tool.Name())
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
		allEvents = append(allEvents, events...)
		if len(errs) > 0 {
			allErrs = append(allErrs, errs...)
		}

		nextTargets := append(currentTargets, extractTargets(events)...)
		normalizedTargets := normalize.DeduplicateAndPreserveURLs(nextTargets)
		currentTargets = scopeGuard.Filter(normalizedTargets)
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
			o.bus.Publish(bus.Event{Target: ev.Target, Source: ev.Source, Type: ev.Type, Properties: ev.Properties})
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

func (o *Orchestrator) runStage(ctx context.Context, tools []Tool, targets []string, threads int) ([]Event, []error) {
	type toolResult struct {
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
				results <- toolResult{err: ctx.Err()}
				return
			}

			defer func() {
				if r := recover(); r != nil {
					results <- toolResult{err: fmt.Errorf("%s panicked: %v", tool.Name(), r)}
				}
			}()

			// Rate limit before executing each tool (initial gate)
			if err := o.limiter.Wait(ctx); err != nil {
				results <- toolResult{err: fmt.Errorf("%s: rate limit cancelled: %w", tool.Name(), err)}
				return
			}
			o.reportToolStatus(tool.Name(), "running", fmt.Sprintf("%d targets", len(targets)))

			var events []Event
			var err error

			if o.fleetRunner != nil {
				slog.Debug("executing tool via axiom fleet", "tool", tool.Name(), "targets", len(targets))
				lines, runErr := o.fleetRunner.RunTool(ctx, tool.Name(), targets, nil)
				if runErr != nil {
					err = runErr
				} else {
					events = NewEventsFromLines(lines, tool.Name(), nil)
				}
			} else {
				slog.Debug("executing tool locally", "tool", tool.Name(), "targets", len(targets), "threads", toolThreads)
				events, err = tool.Run(ctx, targets, toolThreads)
			}

			if err != nil {
				o.reportFailure(tool.Name(), err.Error())
				results <- toolResult{err: fmt.Errorf("%s: %w", tool.Name(), err)}
				return
			}

			slog.Debug("tool complete", "tool", tool.Name(), "events", len(events))
			o.reportToolStatus(tool.Name(), "done", fmt.Sprintf("%d findings", len(events)))
			for _, ev := range events {
				o.reportEvent(ev.Source, ev.Target)
			}
			results <- toolResult{events: events}
		}()
	}

	wg.Wait()
	close(results)

	var events []Event
	var errs []error
	for result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}
		events = append(events, result.events...)
	}
	return events, errs
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
