package cli

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/cluster"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/quota"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
	"golang.org/x/sync/errgroup"
)

// reconResult bundles the outputs of the recon pipeline phase.
type reconResult struct {
	events         []recon.Event
	matches        []recon.Match
	triggeredTools []string
	store          *storage.Storage
	normalized     []string
}

// runReconPipeline contains all recon pipeline logic extracted from executeRun.
func runReconPipeline(ctx context.Context, opts Options, cfg *config.Config, bridge *tui.Bridge, normalized []string, validationEvents []recon.Event, reconThreads int) reconResult {
	result := reconResult{normalized: normalized}

	reconRateLimit := cfg.RateLimit
	if opts.RateLimit > 0 {
		reconRateLimit = opts.RateLimit
	}
	if opts.LowResource && reconRateLimit > 10 {
		reconRateLimit = 10
	}
	if opts.LowResource && reconThreads > 2 {
		reconThreads = 2
	}

	toolNames := strings.Split(opts.Tools, ",")

	// Exclude httpx from the pipeline if it already ran in target validation
	if len(validationEvents) > 0 {
		var filteredTools []string
		for _, t := range toolNames {
			if strings.TrimSpace(strings.ToLower(t)) != "httpx" {
				filteredTools = append(filteredTools, t)
			}
		}
		toolNames = filteredTools
	}

	// Apply tool exclusions
	if opts.ExcludeTools != "" {
		toolNames = FilterExcludedTools(toolNames, opts.ExcludeTools)
		if len(toolNames) == 0 {
			slog.Error("all tools excluded — nothing to run")
			return result
		}
		slog.Info("tools after exclusions applied", "remaining", len(toolNames), "excluded", opts.ExcludeTools)
	}

	if opts.PassiveMode {
		toolNames = filterPassiveTools(toolNames)
	}
	if !opts.ExploitSQLI {
		toolNames = FilterExcludedTools(toolNames, "sqlmap")
	}

	// Build run context with timeout
	var runCtx context.Context
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, opts.Timeout*time.Duration(len(toolNames)))
	} else {
		runCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	runCtx = recon.WithLowResource(runCtx, opts.LowResource)
	runCtx = recon.WithScanMode(runCtx, opts.Mode)
	runCtx = recon.WithHeaders(runCtx, cfg.Headers)
	if cfg.Ports != "" {
		runCtx = recon.WithPorts(runCtx, cfg.Ports)
	}

	eventBus := initEventBus(cfg)
	if eventBus == nil {
		return result
	}
	defer eventBus.Close()

	autoUpdate := cfg.AutoUpdate
	if opts.AutoUpdate {
		autoUpdate = true
	}

	scopeName := opts.Scope
	if scopeName == "" {
		scopeName = "default_run"
	}
	qg := quota.NewQuotaGuard(cfg.StateDir)

	cp, errCheckpoint := utils.NewCheckpoint(cfg.StateDir, scopeName, normalized)
	if errCheckpoint != nil {
		slog.Warn("Failed to initialize checkpointing", "error", errCheckpoint)
	} else {
		if opts.Resume {
			if len(cp.TargetsPending) < len(normalized) {
				slog.Info("Resuming from previous checkpoint", "remaining", len(cp.TargetsPending))
			}
			normalized = cp.TargetsPending
		} else {
			// Clear any previous checkpoint state by resetting to fresh
			cp.TargetsPending = normalized
			cp.TargetsComplete = nil
			cp.CompletedStages = nil
			cp.Events = nil
			cp.CurrentTargets = nil
			cp.Save()
		}
	}

	reconConfig := services.Config{
		ToolNames:          toolNames,
		Threads:            reconThreads,
		RateLimit:          reconRateLimit,
		ToolRateLimits:     cfg.ToolRateLimits,
		AutoUpdate:         autoUpdate,
		Proxies:            cfg.Proxies,
		APIKeys:            cfg.APIKeys,
		WordlistsDir:       cfg.WordlistsDir,
		TmpResultsDir:      resolveTmpResultsDir(opts, cfg),
		Reporter:           bridge,
		Notifier:           utils.NewNotifier(utils.Config(notifierConfigFrom(cfg.Notify))),
		EventBus:           eventBus,
		Timeout:            scanTimeout(opts.Timeout, len(toolNames)),
		CacheEnabled:       true,
		CacheDBPath:        resolveDBSource(cfg),
		ContainerMode:      cfg.ContainerMode,
		DockerImages:       cfg.DockerImages,
		MockMode:           cfg.MockMode,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
		DryRun:             opts.DryRun,
		ExploitSQLI:        opts.ExploitSQLI,
		ForceHTTP1:         opts.ForceHTTP1,
		AssetStore:         opts.AssetStore,
		Checkpoint:         cp,
		QuotaGuard:         qg,
		Fleet: services.FleetConfig{
			Enabled:     opts.EnableFleet || cfg.Fleet.Enabled,
			WorkerMesh:  cfg.Fleet.WorkerMesh,
			FleetName:   cfg.Fleet.FleetName,
			FleetSize:   cfg.Fleet.FleetSize,
			DeleteAfter: cfg.Fleet.DeleteAfter,
		},
		FPConfidenceThreshold: func() int {
			if opts.FPThreshold >= 0 {
				return opts.FPThreshold
			}
			return cfg.FPConfidenceThreshold
		}(),
		FPKeepSuppressed: opts.IncludeFP || cfg.FPKeepSuppressed,
		FPAudit:          opts.FPAudit,
	}
	if err := writeSeedDomainsToTmp(reconConfig.TmpResultsDir, normalized); err != nil {
		slog.Warn("failed to persist seed domains", "error", err, "dir", reconConfig.TmpResultsDir)
	}

	orchestrator := services.NewOrchestrator(reconConfig)
	defer orchestrator.Close()

	// Spin up Storage and subscriber for asynchronous event streaming
	result.store = initStorage(runCtx, cfg, orchestrator)

	if bridge != nil {
		bridge.SendThreadCount(reconThreads, cfg.Threads)
		bridge.SendRateLimit(reconRateLimit)
		bridge.ReportToolStatus("engine", "running", "starting recon pipeline")
	}

	// Execute the scan
	var events []recon.Event
	events = executeReconScan(runCtx, opts, orchestrator, normalized, validationEvents, cp, reconThreads)

	if cp != nil {
		cp.Clear()
	}

	events = cluster.DedupeEvents(events)
	if opts.LightMode {
		if err := writeModePipelineArtifacts("results", normalized, events); err != nil {
			slog.Warn("failed to write mode pipeline artifacts", "error", err)
		}
		if err := writeModePipelineArtifacts("output", normalized, events); err != nil {
			slog.Warn("failed to write output mode pipeline artifacts", "error", err)
		}
	}
	if bridge != nil {
		bridge.ReportToolStatus("engine", "done", "recon pipeline complete")
	}

	// --- Persistence & Rules ---
	ruleSet, _ := recon.LoadFromFile(opts.RulesPath)
	if ruleSet == nil {
		ruleSet = recon.DefaultRules()
	}

	result.events = events
	result.matches, result.triggeredTools = ruleSet.Evaluate(events)
	result.normalized = normalized

	handleDiffReporting(opts, cfg, normalized, events, &result)

	return result
}

// filterPassiveTools removes active-scanning tools from the pipeline.
func filterPassiveTools(toolNames []string) []string {
	activeBlacklist := map[string]bool{
		"naabu":       true,
		"nuclei":      true,
		"dalfox":      true,
		"ffuf":        true,
		"gobuster":    true,
		"feroxbuster": true,
		"katana":      true,
		"httpx":       true,
	}
	var passiveTools []string
	for _, t := range toolNames {
		tLower := strings.TrimSpace(strings.ToLower(t))
		if !activeBlacklist[tLower] {
			passiveTools = append(passiveTools, t)
		}
	}
	slog.Info("Passive mode enabled. Active tools filtered out.", "original_count", len(toolNames), "passive_count", len(passiveTools))
	return passiveTools
}

// initEventBus creates the event bus from configuration.
func initEventBus(cfg *config.Config) queue.EventBus {
	busType := cfg.EventBus.Type
	if busType == "" {
		busType = "in-memory"
	}
	switch busType {
	case "nats":
		url := cfg.EventBus.URL
		if url == "" {
			url = "nats://127.0.0.1:4222"
		}
		eventBus, err := queue.NewNatsBus(url)
		if err != nil {
			slog.Warn("NATS event bus unavailable; falling back to in-memory bus", "error", err)
			return queue.New()
		}
		slog.Info("NATS event bus enabled", "url", url)
		return eventBus
	case "in-memory":
		slog.Warn("Using in-memory event bus; fleet distributed worker mode will be disabled.")
		return queue.New()
	default:
		slog.Warn("Invalid event bus type, falling back to in-memory bus", "type", cfg.EventBus.Type)
		return queue.New()
	}
}

func resolveDBSource(cfg *config.Config) string {
	dbType := cfg.Database.Type
	if dbType == "" {
		dbType = "sqlite3"
	}
	dbSource := cfg.Database.DSN
	if dbSource == "" && (dbType == "sqlite3" || dbType == "sqlite") {
		home, _ := os.UserHomeDir()
		dbSource = filepath.Join(home, ".bbpts", "bbpts.db")
	}
	return dbSource
}

// initStorage creates and wires the Storage instance + CTEM escalator.
func initStorage(ctx context.Context, cfg *config.Config, orchestrator *services.Orchestrator) *storage.Storage {
	dbType := cfg.Database.Type
	if dbType == "" {
		dbType = "sqlite3"
	}
	dbSource := resolveDBSource(cfg)

	store, err := storage.NewStorage(dbType, dbSource)
	if err != nil {
		slog.Warn("Failed to initialize Recon Memory storage", "error", err, "db_type", dbType)
		return nil
	}

	ctx = storage.WithStorage(ctx, store)
	sub := storage.NewEventSubscriber(store, orchestrator.Bus())
	sub.Start(ctx, []string{
		"graphql_endpoint", "cloud_bucket_open", "secret_exposed",
		"port_open", "vulnerability", "discovery", "subdomain",
		queue.EventAssetDiscovered,
		queue.EventHostAlive,
		queue.EventFindingCreated,
		queue.EventFindingVerified,
		queue.EventFindingClosed,
		queue.EventRiskChanged,
		queue.EventOwnerAssigned,
	})

	// Start background CTEM Escalator
	escalator := services.NewEscalator(store, 1*time.Hour)
	escalator.Start(ctx)

	slog.Info("Recon Memory and CTEM Escalator enabled", "db_type", dbType, "source", dbSource)
	return store
}

// executeReconScan runs the scan with batch/lowresource/normal modes.
func executeReconScan(ctx context.Context, opts Options, orchestrator *services.Orchestrator, normalized []string, validationEvents []recon.Event, cp *utils.Checkpoint, _ int) []recon.Event {
	var events []recon.Event

	if opts.LowResource && len(normalized) > 50 {
		events = append([]recon.Event{}, validationEvents...)
		for i := 0; i < len(normalized); i += 20 {
			end := i + 20
			if end > len(normalized) {
				end = len(normalized)
			}
			batchTargets := normalized[i:end]
			batchEvents, err := orchestrator.Run(ctx, batchTargets)
			if err != nil {
				slog.Warn("recon batch completed with tool errors", "error", err, "batch_start", i, "batch_end", end)
			}
			events = append(events, convertServicesEventsToRecon(batchEvents)...)
			if cp != nil {
				for _, t := range batchTargets {
					cp.MarkComplete(t)
				}
			}
			runtime.GC()
		}
	} else if batchSize := opts.BatchSize; batchSize > 1 {
		// Batch parallelism: run multiple domain groups concurrently
		var allEvents []services.Event
		var eventsMu sync.Mutex
		eg, egCtx := errgroup.WithContext(ctx)
		eg.SetLimit(batchSize)

		chunkSize := (len(normalized) + batchSize - 1) / batchSize
		if chunkSize < 1 {
			chunkSize = 1
		}
		for i := 0; i < len(normalized); i += chunkSize {
			end := i + chunkSize
			if end > len(normalized) {
				end = len(normalized)
			}
			batch := normalized[i:end]
			eg.Go(func() error {
				batchEvents, err := orchestrator.Run(egCtx, batch)
				if err != nil {
					slog.Warn("batch completed with errors", "error", err, "batch_size", len(batch))
				}
				eventsMu.Lock()
				allEvents = append(allEvents, batchEvents...)
				eventsMu.Unlock()
				if cp != nil {
					for _, t := range batch {
						cp.MarkComplete(t)
					}
				}
				return nil
			})
		}
		if err := eg.Wait(); err != nil {
			slog.Warn("batch parallelism completed with errors", "error", err)
		}
		events = append(validationEvents, convertServicesEventsToRecon(allEvents)...)
	} else {
		servicesEvents, err := orchestrator.Run(ctx, normalized)
		events = append(validationEvents, convertServicesEventsToRecon(servicesEvents)...)
		if err != nil {
			slog.Warn("recon completed with tool errors", "error", err)
		}
		if cp != nil {
			for _, t := range normalized {
				cp.MarkComplete(t)
			}
		}
	}

	return events
}

// handleDiffReporting computes diff and writes diff markdown if scope is set.
func handleDiffReporting(opts Options, cfg *config.Config, normalized []string, events []recon.Event, result *reconResult) {
	diff, _ := handlePersistence(opts, cfg, normalized, events)
	if diff != nil && opts.Scope != "" {
		diffMD := diff.ToMarkdown(opts.Scope)
		reportDir := "results"
		if strings.TrimSpace(opts.OutputPath) != "" {
			reportDir = filepath.Dir(opts.OutputPath)
		}
		_ = os.MkdirAll(reportDir, 0700)
		diffPath := filepath.Join(reportDir, fmt.Sprintf("%s_diff.md", opts.Scope))
		if err := os.WriteFile(diffPath, []byte(diffMD), 0600); err != nil {
			slog.Error("failed to write diff markdown report", "path", diffPath, "error", err)
		} else {
			slog.Info("diff markdown report written", "path", diffPath)
		}
		if opts.CronInterval > 0 && (len(diff.NewTargets) > 0 || len(diff.NewEvents) > 0 || len(diff.RiskChanges) > 0 || len(diff.NewlyExposed) > 0) {
			fmt.Println("\n=== DIFFERENTIAL RECONNAISSANCE REPORT ===")
			fmt.Print(diffMD)
			fmt.Println("==========================================")
			fmt.Println()
		}
	}
	if diff != nil && opts.DiffOnly {
		result.events = diff.NewEvents
		result.normalized = diff.NewTargets
		// Re-evaluate recon on the diff
		ruleSet, _ := recon.LoadFromFile(opts.RulesPath)
		if ruleSet == nil {
			ruleSet = recon.DefaultRules()
		}
		result.matches, result.triggeredTools = ruleSet.Evaluate(result.events)
	}
}
