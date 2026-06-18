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
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/server"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/sync/errgroup"
)

// Run executes the BBPTS engine with the provided options.
func Run(ctx context.Context, opts Options, cfg *config.Config, bridge *tui.Bridge, tuiProgram *tea.Program) {
	if opts.UseTUI && tuiProgram != nil {
		go func() {
			runLoop(ctx, opts, cfg, bridge)
			if opts.CronInterval <= 0 && bridge != nil {
				bridge.CompleteSession()
			}
		}()

		if _, err := tuiProgram.Run(); err != nil {
			slog.Error("BBPTS TUI error", "error", err)
			os.Exit(1)
		}
	} else if opts.RunWorker {
		runWorkerNode(ctx, opts, cfg)
	} else {
		runLoop(ctx, opts, cfg, bridge)
	}
}

func runLoop(ctx context.Context, opts Options, cfg *config.Config, bridge *tui.Bridge) {
	for {
		executeRun(ctx, opts, cfg, bridge)
		if opts.CronInterval <= 0 {
			break
		}
		slog.Info("continuous monitoring: sleeping until next run", "interval_minutes", opts.CronInterval)
		time.Sleep(time.Duration(opts.CronInterval) * time.Minute)
	}
}

func executeRun(ctx context.Context, opts Options, cfg *config.Config, bridge *tui.Bridge) {
	abortCtx, cancelAbort := context.WithCancel(ctx)
	defer cancelAbort()
	abortCtx = services.WithDryRun(abortCtx, opts.DryRun)

	// Monitor ScanAbortChan to cancel abortCtx
	go func() {
		select {
		case <-tui.ScanAbortChan:
			cancelAbort()
		case <-abortCtx.Done():
		}
	}()

	var events []recon.Event
	var matches []recon.Match
	var triggeredTools []string
	var store *storage.Storage

	reconThreads := cfg.Threads
	if opts.Threads > 0 {
		reconThreads = opts.Threads
	}

	// Create a default context for reporting if scan is skipped
	runCtx, cancel := context.WithCancel(abortCtx)
	defer cancel()

	normalized, validationEvents, ok := parseAndValidateTargets(abortCtx, &opts, cfg, bridge, reconThreads)
	if !ok {
		return
	}

	if len(normalized) > 0 {
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
				return
			}
			slog.Info("tools after exclusions applied", "remaining", len(toolNames), "excluded", opts.ExcludeTools)
		}

		if opts.PassiveMode {
			var passiveTools []string
			activeBlacklist := map[string]bool{
				"naabu":       true,
				"nuclei":      true,
				"dalfox":      true,
				"ffuf":        true,
				"gobuster":    true,
				"feroxbuster": true,
				"katana":      true,
			}
			for _, t := range toolNames {
				tLower := strings.TrimSpace(strings.ToLower(t))
				if !activeBlacklist[tLower] {
					passiveTools = append(passiveTools, t)
				}
			}
			slog.Info("Passive mode enabled. Active tools filtered out.", "original_count", len(toolNames), "passive_count", len(passiveTools))
			toolNames = passiveTools
		}

		// Re-initialize context with proper timeout for tools
		cancel()
		if opts.Timeout > 0 {
			runCtx, cancel = context.WithTimeout(abortCtx, opts.Timeout*time.Duration(len(toolNames)))
			defer cancel()
		} else {
			runCtx, cancel = context.WithCancel(abortCtx)
			defer cancel()
		}

		runCtx = services.WithLowResource(runCtx, opts.LowResource)
		runCtx = services.WithScanMode(runCtx, opts.Mode)
		runCtx = services.WithHeaders(runCtx, cfg.Headers)
		if cfg.Ports != "" {
			runCtx = services.WithPorts(runCtx, cfg.Ports)
		}

		var eventBus queue.EventBus
		busType := cfg.EventBus.Type
		if busType == "" {
			busType = "nats"
		}
		switch busType {
		case "nats":
			url := cfg.EventBus.URL
			if url == "" {
				url = "nats://127.0.0.1:4222"
			}
			var err error
			eventBus, err = queue.NewNatsBus(url)
			if err != nil {
				if !cfg.MockMode {
					slog.Error("NATS event bus required for production but unavailable", "error", err)
					os.Exit(1)
				}
				slog.Warn("NATS event bus unavailable; falling back to in-memory bus for mock mode", "error", err)
				eventBus = queue.New()
			} else {
				defer eventBus.Close()
				slog.Info("NATS event bus enabled", "url", url)
			}
		case "in-memory":
			if !cfg.MockMode {
				slog.Error("in-memory event bus is not allowed in production; NATS must be configured")
				os.Exit(1)
			}
			eventBus = queue.New()
		default:
			slog.Error("Invalid event bus type", "type", cfg.EventBus.Type)
			os.Exit(1)
		}

		autoUpdate := cfg.AutoUpdate
		if opts.AutoUpdate {
			autoUpdate = true
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
			ContainerMode:      cfg.ContainerMode,
			DockerImages:       cfg.DockerImages,
			MockMode:           cfg.MockMode,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			DryRun:             opts.DryRun,
			AssetStore:         opts.AssetStore,
			Fleet: services.FleetConfig{
				Enabled:     opts.EnableFleet || cfg.Fleet.Enabled,
				WorkerMesh:  cfg.Fleet.WorkerMesh,
				FleetName:   cfg.Fleet.FleetName,
				FleetSize:   cfg.Fleet.FleetSize,
				DeleteAfter: cfg.Fleet.DeleteAfter,
			},
		}
		if err := writeSeedDomainsToTmp(reconConfig.TmpResultsDir, normalized); err != nil {
			slog.Warn("failed to persist seed domains", "error", err, "dir", reconConfig.TmpResultsDir)
		}

		orchestrator := services.NewOrchestrator(reconConfig)
		defer orchestrator.Close()

		// Spin up Storage and subscriber for asynchronous event streaming
		dbType := cfg.Database.Type
		if dbType == "" {
			dbType = "sqlite3"
		}
		dbSource := cfg.Database.DSN
		if dbSource == "" && (dbType == "sqlite3" || dbType == "sqlite") {
			home, _ := os.UserHomeDir()
			dbSource = filepath.Join(home, ".bbpts", "bbpts.db")
		}

		var err error
		store, err = storage.NewStorage(dbType, dbSource)
		if err == nil {
			defer store.Close()
			runCtx = storage.WithStorage(runCtx, store)
			sub := storage.NewEventSubscriber(store, orchestrator.Bus())
			sub.Start(runCtx, []string{
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
			defer sub.Stop()

			// Start background CTEM Escalator
			escalator := services.NewEscalator(store, 1*time.Hour)
			escalator.Start(runCtx)
			defer escalator.Stop()

			slog.Info("Recon Memory and CTEM Escalator enabled", "db_type", dbType, "source", dbSource)
		} else {
			slog.Warn("Failed to initialize Recon Memory storage", "error", err, "db_type", dbType)
		}

		if bridge != nil {
			bridge.SendThreadCount(reconThreads, cfg.Threads)
			bridge.SendRateLimit(reconRateLimit)
			bridge.ReportToolStatus("engine", "running", "starting recon pipeline")
		}

		scopeName := opts.Scope
		if scopeName == "" {
			scopeName = "default_run"
		}
		cp, err := utils.NewCheckpoint(cfg.StateDir, scopeName, normalized)
		if err != nil {
			slog.Warn("Failed to initialize checkpointing", "error", err)
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
				cp.Save()
			}
		}

		if opts.LowResource && len(normalized) > 50 {
			events = append([]recon.Event{}, validationEvents...)
			for i := 0; i < len(normalized); i += 20 {
				end := i + 20
				if end > len(normalized) {
					end = len(normalized)
				}
				batchTargets := normalized[i:end]
				batchEvents, err := orchestrator.Run(runCtx, batchTargets)
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
			eg, egCtx := errgroup.WithContext(runCtx)
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
			servicesEvents, err := orchestrator.Run(runCtx, normalized)
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

		matches, triggeredTools = ruleSet.Evaluate(events)
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
			events = diff.NewEvents
			normalized = diff.NewTargets
			// Re-evaluate recon on the diff
			matches, triggeredTools = ruleSet.Evaluate(events)
		}
	} else {
		slog.Info("no input provided; skipping reconnaissance scan")
		if bridge != nil {
			bridge.ReportToolStatus("engine", "done", "no input; scan skipped")
		}
	}

	// --- Dashboard Phase ---
	var dashboardDone chan struct{}
	if opts.EnableDashboard {
		dashboardDone = make(chan struct{})
		store, err := utils.NewStore(cfg.StateDir, true)
		if err != nil {
			slog.Error("failed to open store for dashboard", "error", err)
		} else {
			if storage := store.GetDB(); storage != nil {
				go func() {
					defer close(dashboardDone)
					dbType := cfg.Database.Type
					if dbType == "" {
						dbType = "sqlite3"
					}
					dbSource := cfg.Database.DSN
					if dbSource == "" && (dbType == "sqlite3" || dbType == "sqlite") {
						home, _ := os.UserHomeDir()
						dbSource = filepath.Join(home, ".bbpts", "bbpts.db")
					}
					tlsEnabled := opts.TLSEnabled || cfg.DashboardTLS.Enabled
					certFile := opts.TLSCertFile
					if certFile == "" {
						certFile = cfg.DashboardTLS.CertFile
					}
					keyFile := opts.TLSKeyFile
					if keyFile == "" {
						keyFile = cfg.DashboardTLS.KeyFile
					}
					serverCfg := server.Config{
						Port:        opts.DashboardPort,
						TLSEnabled:  tlsEnabled,
						TLSCertFile: certFile,
						TLSKeyFile:  keyFile,
					}
					if err := server.Start(serverCfg, storage, opts.ConfigPath, dbSource); err != nil {
						slog.Error("dashboard server error", "error", err)
					}
				}()
			}
		}
	}

	// --- Final Intelligence & Reporting ---
	events = handleIntelligence(runCtx, opts, cfg, store, events, matches, triggeredTools, reconThreads, bridge)
	handleReporting(runCtx, opts, cfg, store, normalized, events, matches, bridge)

	// If dashboard is enabled and not in cron mode, wait for it
	if opts.EnableDashboard && opts.CronInterval <= 0 && dashboardDone != nil {
		slog.Info("dashboard is active. press 'q' or Ctrl+C to stop.")

		// Simple terminal listener for 'q'
		go func() {
			var b [1]byte
			for {
				n, err := os.Stdin.Read(b[:])
				if err != nil {
					slog.Warn("stdin read failed", "error", err)
					cancel()
					return
				}
				if n > 0 && b[0] == 'q' {
					slog.Info("exit signal received; stopping dashboard...")
					cancel() // Stop everything
					return
				}
			}
		}()

		<-dashboardDone
	}
}
