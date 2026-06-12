// Package cli provides CLI interface components
package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/baseline"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/cluster"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/triage"

	"github.com/Developer-Army/BBPTS/internal/domain/ownership"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	ui "github.com/Developer-Army/BBPTS/internal/interfaces/ui/report"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/server"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/interfaces/workers"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/input"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/sync/errgroup"
)

func notifierConfigFrom(cfg config.NotifyConfig) utils.Config {
	return utils.Config{
		TelegramBotToken: cfg.TelegramBotToken,
		TelegramChatID:   cfg.TelegramChatID,
		DiscordWebhook:   cfg.DiscordWebhook,
		SlackWebhook:     cfg.SlackWebhook,
	}
}

// Options holds all runtime parameters for the BBPTS engine.
type Options struct {
	InputPath         string
	Tools             string
	OutputPath        string
	SummaryPath       string
	ObsidianDir       string
	ObsidianName      string
	Timeout           time.Duration
	Debug             bool
	Threads           int
	ConfigPath        string
	RateLimit         int
	Scope             string
	DiffOnly          bool
	RulesPath         string
	SkipRules         bool
	EnableFingerprint bool
	EnableFleet       bool
	EnableDashboard   bool
	DashboardPort     int
	ReportH1          string
	ReportBC          string
	ExportBurp        string
	CronInterval      int
	LowResource       bool
	UseTUI            bool
	RunDoctor         bool
	Preset            string
	Profile           string
	Mode              string
	EvidencePath      string
	EvidenceTopN      int
	LightMode         bool
	FullMode          bool
	RunWorker         bool
	Submit            bool
	TLSEnabled        bool
	TLSCertFile       string
	TLSKeyFile        string
	WebEnder          string
	ShowVersion       bool
	EnableMetrics     bool
	MetricsPort       int
	LogFilePath       string
	Headers           string
	MaxCPUPercent     int
	MaxCPUCores       int
	MaxMemoryMB       int
	GCPercent         int
	Resume            bool
	JSONOutput        bool
	AutoUpdate        bool
	ExcludeTools      string
	BatchSize         int
	LogLevel          string
	ReportTemplate    string
}

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

func runWorkerNode(ctx context.Context, opts Options, cfg *config.Config) {
	slog.Info("Starting BBPTS in Stateless Worker Mode")

	if cfg.EventBus.URL == "" {
		slog.Error("Cannot start worker node: NATS EventBus URL is required in config")
		os.Exit(1)
	}

	streamMgr, err := queue.NewStreamManager(cfg.EventBus.URL)
	if err != nil {
		slog.Error("Failed to connect to event stream", "error", err)
		os.Exit(1)
	}
	defer streamMgr.Close()

	leaseMgr, err := queue.NewLeaseManager(streamMgr.JetStream(), "WORKER_LEASES")
	if err != nil {
		slog.Error("Failed to initialize lease manager", "error", err)
		os.Exit(1)
	}

	idempotencyMgr, err := queue.NewIdempotencyManager(streamMgr.JetStream(), "TASK_IDEMPOTENCY")
	if err != nil {
		slog.Error("Failed to initialize idempotency manager", "error", err)
		os.Exit(1)
	}

	workerID := fmt.Sprintf("node-%d", time.Now().UnixNano())
	caps := []workers.CapabilityType{
		workers.CapSubdomainEnum,
		workers.CapPortScan,
		workers.CapBrowserRecon,
		workers.CapJSDiff,
	}

	node := workers.NewWorker(workerID, streamMgr, leaseMgr, caps)
	node.IdempotencyMgr = idempotencyMgr
	if err := node.Start(ctx); err != nil {
		slog.Error("Failed to start worker node heartbeat", "error", err)
		os.Exit(1)
	}

	executor := workers.NewExecutor(node)

	// Register Real Distributed Handlers
	registerRealHandlers(ctx, executor, cfg)

	slog.Info("Worker waiting for tasks... (Press Ctrl+C to exit)", "id", workerID)

	if err := executor.Run(ctx); err != nil {
		slog.Error("Worker executor encountered a fatal error", "error", err)
	}
}

func executeRun(ctx context.Context, opts Options, cfg *config.Config, bridge *tui.Bridge) {
	abortCtx, cancelAbort := context.WithCancel(ctx)
	defer cancelAbort()

	// Monitor ScanAbortChan to cancel abortCtx
	go func() {
		select {
		case <-tui.ScanAbortChan:
			cancelAbort()
		case <-abortCtx.Done():
		}
	}()

	var normalized []string
	var events []recon.Event
	var validationEvents []recon.Event
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

	// --- Reconnaissance Phase ---
	if opts.InputPath != "" {
		// Accept a raw URL or hostname directly with -i, no file required.
		if isDirectURL(opts.InputPath) {
			normalized = []string{opts.InputPath}
		} else {
			if strings.TrimSpace(opts.OutputPath) == "" && strings.TrimSpace(opts.SummaryPath) == "" {
				opts.OutputPath, opts.SummaryPath = defaultReportPaths(opts.InputPath)
				slog.Info("no report paths provided; using defaults", "output", opts.OutputPath, "summary", opts.SummaryPath)
			}

			if bridge != nil {
				bridge.ReportToolStatus("engine", "running", "parsing input targets")
			}
			parser := input.NewParser()
			metadataTargets, err := parser.ParseFileWithMetadata(opts.InputPath)
			if err != nil {
				slog.Error("failed to parse input", "error", err)
				if bridge != nil {
					bridge.ReportFailure("engine", "failed to parse input")
				}
				return
			}

			rawTargets := make([]string, 0, len(metadataTargets))
			for _, target := range metadataTargets {
				if !target.IsInScope() {
					continue
				}
				rawTargets = append(rawTargets, target.URL)
			}

			// Preserve full URLs from input (including paths) for web probing.
			normalized = normalize.DeduplicateAndPreserveURLs(rawTargets)
			if len(normalized) == 0 {
				slog.Warn("no in-scope targets were found in the input file")
				if bridge != nil {
					bridge.ReportFailure("engine", "no in-scope targets found")
				}
				return
			}
		}
		if bridge != nil {
			bridge.SendInitialTargets(normalized)
		}
	} else if bridge != nil {
		bridge.PromptForTarget()
		select {
		case targets := <-tui.TargetInputChan:
			select {
			case selectedMode := <-tui.TargetModeChan:
				opts.Mode = selectedMode
				opts.LightMode = (selectedMode == "light")
				opts.FullMode = (selectedMode == "normal")
			default:
				opts.Mode = "normal"
			}
			opts.Tools = ToolsetForMode(opts.Mode)
			normalized = targets
			if strings.TrimSpace(opts.OutputPath) == "" && strings.TrimSpace(opts.SummaryPath) == "" {
				opts.OutputPath, opts.SummaryPath = defaultReportPaths(targets[0])
				slog.Info("no report paths provided; using defaults", "output", opts.OutputPath, "summary", opts.SummaryPath)
			}
			bridge.SendInitialTargets(normalized)
		case <-ctx.Done():
			return
		}
	}

	if len(normalized) > 0 {
		normalized, validationEvents = validateTargetsWithHTTPX(abortCtx, normalized, reconThreads)
		if len(normalized) == 0 {
			slog.Warn("No valid targets active or resolved via httpx validation. Aborting run.")
			if bridge != nil {
				bridge.ReportFailure("engine", "all targets failed validation")
			}
			return
		}
	}

	if len(normalized) > 0 {
		if opts.Profile != "" && cfg.ProgramProfiles != nil {
			if prof, ok := cfg.ProgramProfiles[opts.Profile]; ok {
				before := len(normalized)
				normalized = config.FilterTargets(normalized, prof)
				if before != len(normalized) {
					slog.Info("program profile applied", "profile", opts.Profile, "targets_after_filter", len(normalized))
				}
				if len(normalized) == 0 {
					slog.Warn("all targets excluded by program profile", "profile", opts.Profile)
					return
				}
			}
		}

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
		if busType == "nats" {
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
		} else if busType == "in-memory" {
			if !cfg.MockMode {
				slog.Error("in-memory event bus is not allowed in production; NATS must be configured")
				os.Exit(1)
			}
			eventBus = queue.New()
		} else {
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

func defaultReportPaths(inputPath string) (string, string) {
	base := strings.TrimSpace(filepath.Base(inputPath))
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if strings.TrimSpace(name) == "" {
		name = "scan"
	}
	return filepath.Join("results", name+"_report.md"), filepath.Join("results", name+"_summary.csv")
}

func writeSeedDomainsToTmp(tmpDir string, targets []string) error {
	if strings.TrimSpace(tmpDir) == "" {
		return nil
	}
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return err
	}

	domains := extractSeedDomains(targets)
	if len(domains) == 0 {
		return nil
	}

	path := filepath.Join(tmpDir, "seed_domains.txt")
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, domain := range domains {
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func extractSeedDomains(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))

	for _, target := range targets {
		domain := domainFromTarget(target)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

func domainFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return ""
		}
		host := strings.ToLower(strings.Split(u.Host, ":")[0])
		if !isValidSeedHostname(host) {
			return ""
		}
		return host
	}

	trimmed := strings.Split(target, "/")[0]
	if strings.Contains(trimmed, " ") {
		return ""
	}
	host := strings.ToLower(strings.Split(trimmed, ":")[0])
	if !isValidSeedHostname(host) {
		return ""
	}
	return host
}

func isValidSeedHostname(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, " /\\") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func scanTimeout(perTool time.Duration, toolCount int) time.Duration {
	if perTool <= 0 {
		return 0
	}
	if toolCount < 1 {
		toolCount = 1
	}
	return perTool * time.Duration(toolCount)
}

func resolveTmpResultsDir(opts Options, cfg *config.Config) string {
	if opts.LightMode {
		return filepath.Join("results", "tmp")
	}
	if cfg != nil && strings.TrimSpace(cfg.TmpResultsDir) != "" {
		return cfg.TmpResultsDir
	}

	baseDir := "."
	if strings.TrimSpace(opts.OutputPath) != "" {
		baseDir = filepath.Dir(opts.OutputPath)
	} else if strings.TrimSpace(opts.SummaryPath) != "" {
		baseDir = filepath.Dir(opts.SummaryPath)
	}
	if baseDir == "results" || baseDir == "./results" {
		return filepath.Join(baseDir, "tmp")
	}
	return filepath.Join(baseDir, "results", "tmp")
}

func writeModePipelineArtifacts(outputDir string, seedTargets []string, events []recon.Event) error {
	if strings.TrimSpace(outputDir) == "" {
		return nil
	}
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return err
	}

	rootDomains := extractSeedDomains(seedTargets)
	if err := writeLines(filepath.Join(outputDir, "root_domains.txt"), rootDomains); err != nil {
		return err
	}

	passive := make([]string, 0)
	resolved := make([]string, 0)
	liveHosts := make([]string, 0)
	services := make([]string, 0)
	combined := make([]string, 0)
	normalized := make([]string, 0)

	for _, ev := range events {
		target := strings.TrimSpace(ev.Target)
		if target == "" {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(ev.Source))
		switch source {
		case "assetfinder", "crtsh", "subfinder", "chaos":
			passive = append(passive, domainFromTarget(target))
		case "dnsx":
			resolved = append(resolved, domainFromTarget(target))
		case "httpx":
			if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
				liveHosts = append(liveHosts, target)
			}
		case "naabu":
			services = append(services, target)
		case "gau", "katana", "hakrawler", "feroxbuster", "ffuf":
			if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
				combined = append(combined, target)
			}
		case "uro":
			if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
				normalized = append(normalized, target)
			}
		}
	}

	passive = append(passive, rootDomains...)
	if err := writeLines(filepath.Join(outputDir, "recon.txt"), passive); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "resolved_subdomains.txt"), resolved); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "live_hosts.txt"), liveHosts); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "services.txt"), services); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "combined_urls.txt"), combined); err != nil {
		return err
	}
	if len(normalized) == 0 {
		normalized = combined
	}
	return writeLines(filepath.Join(outputDir, "normalized_urls.txt"), normalized)
}

func writeLines(path string, lines []string) error {
	seen := make(map[string]struct{}, len(lines))
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		v := strings.TrimSpace(line)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		clean = append(clean, v)
	}
	sort.Strings(clean)

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, line := range clean {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func handlePersistence(opts Options, cfg *config.Config, normalized []string, events []recon.Event) (*utils.Diff, error) {
	if opts.Scope == "" {
		return nil, nil
	}
	store, err := utils.NewStore(cfg.StateDir, true)
	if err != nil {
		slog.Error("failed to open utils store", "error", err)
		return nil, err
	}
	defer store.Close()

	diff, err := store.ComputeDiff(opts.Scope, normalized, events)
	if err != nil {
		slog.Warn("failed to compute diff", "error", err)
	}

	if err := store.Save(opts.Scope, normalized, events); err != nil {
		slog.Error("failed to save utils", "error", err)
	}

	if diff != nil && opts.DiffOnly {
		slog.Info("diff computed", "new_targets", len(diff.NewTargets), "new_events", len(diff.NewEvents))
	}

	return diff, nil
}

func handleIntelligence(ctx context.Context, opts Options, cfg *config.Config, store *storage.Storage, events []recon.Event, matches []recon.Match, triggeredTools []string, threads int, bridge *tui.Bridge) []recon.Event {
	slog.Info("Running Advanced Offensive Intelligence Engine")

	te := triage.NewTriageEngine()
	scorer := recon.NewScorer()

	// Convert events to findings
	findings := make([]*triage.Finding, len(events))
	for i, ev := range events {
		findings[i] = &triage.Finding{
			Type:   ev.Type,
			Target: ev.Target,
			Source: ev.Source,
		}
	}

	// Filter noise and prioritize
	actionable := te.FilterNoise(findings)
	prioritized := te.PrioritizeFindings(actionable)

	// Keep a map from type:target to original event to preserve original properties
	eventMap := make(map[string]recon.Event)
	for _, ev := range events {
		key := fmt.Sprintf("%s:%s", ev.Type, ev.Target)
		eventMap[key] = ev
	}

	// Convert back to events, scoring HTTP endpoints along the way
	triagedEvents := make([]recon.Event, 0, len(prioritized))
	for _, f := range prioritized {
		key := fmt.Sprintf("%s:%s", f.Type, f.Target)
		ev, ok := eventMap[key]
		if !ok {
			ev = recon.Event{
				Type:   f.Type,
				Target: f.Target,
				Source: f.Source,
			}
		}

		if strings.HasPrefix(ev.Target, "http") {
			var hasOwner, hasAttackPath bool
			var evidenceCount int
			var exploitability int
			var isAuthRequired bool

			if ev.Properties != nil {
				if val, ok := ev.Properties["auth_required"]; ok && val == "true" {
					isAuthRequired = true
				} else if val, ok := ev.Properties["authenticated"]; ok && val == "true" {
					isAuthRequired = true
				}
			}

			if store != nil {
				if asset, err := store.GetAsset(ev.Target); err == nil && asset != nil {
					ao := &ownership.AssetOwnership{
						AssetID: asset.ID,
					}
					if asset.OwnerID != nil {
						ao.OwnerID = *asset.OwnerID
						ao.Confidence = asset.Confidence
					}
					hasOwner = !ao.IsUnmanagedRisk()
				}

				if evs, err := store.GetEvidenceByAssetID(ev.Target); err == nil {
					evidenceCount = len(evs)
				}

				if db := store.GetDB(); db != nil {
					var count int
					nodeID := storage.GenerateNodeID("domain", ev.Target, "")
					err := db.QueryRow("SELECT COUNT(*) FROM asset_edges WHERE target_id = ? OR target_id = ?", ev.Target, nodeID).Scan(&count)
					if err == nil && count > 0 {
						hasAttackPath = true
					}
				}
			}

			score := scorer.ScoreEndpointAdvanced(ev.Target, isAuthRequired, "", hasOwner, hasAttackPath, evidenceCount, exploitability)
			if store != nil {
				if history, err := store.GetFindingHistory(ctx, ev.Target, 50, 0); err == nil {
					scorer.AdjustScoreWithHistory(score, len(history))
				}
			}
			if score.Score > 0 {
				slog.Info("High Value Target Prioritized", "target", ev.Target, "severity", score.Severity, "score", score.Score, "reasons", score.Justification)
				if ev.Properties == nil {
					ev.Properties = make(map[string]string)
				}
				ev.Properties["scorer_score"] = fmt.Sprintf("%d", score.Score)
				ev.Properties["scorer_severity"] = score.Severity
				ev.Properties["scorer_justification"] = strings.Join(score.Justification, ", ")
				ev.Properties["scorer_exposure"] = fmt.Sprintf("%d", score.ExposureScore)
				ev.Properties["scorer_attackability"] = fmt.Sprintf("%d", score.AttackabilityScore)
				ev.Properties["scorer_business_impact"] = fmt.Sprintf("%d", score.BusinessImpactScore)
				ev.Properties["scorer_confidence"] = fmt.Sprintf("%d", score.ConfidenceScore)
				ev.Properties["scorer_freshness"] = fmt.Sprintf("%d", score.FreshnessScore)
				ev.Properties["scorer_path_score"] = fmt.Sprintf("%d", score.PathScore)
				if vectorJSON, err := json.Marshal(score.Risk); err == nil {
					ev.Properties["scorer_risk_vector"] = string(vectorJSON)
				}
			}
		}
		triagedEvents = append(triagedEvents, ev)
	}

	if len(triggeredTools) > 0 {
		slog.Info("recon triggered additional tools", "count", len(triggeredTools), "tools", triggeredTools)
		// Extract targets from triagedEvents
		var triagedTargets []string
		seenTargets := make(map[string]struct{})
		for _, ev := range triagedEvents {
			if _, ok := seenTargets[ev.Target]; !ok {
				seenTargets[ev.Target] = struct{}{}
				triagedTargets = append(triagedTargets, ev.Target)
			}
		}

		if len(triagedTargets) > 0 {
			reconConfig := services.Config{
				ToolNames:     triggeredTools,
				Threads:       threads,
				RateLimit:     opts.RateLimit,
				Proxies:       cfg.Proxies,
				APIKeys:       cfg.APIKeys,
				WordlistsDir:  cfg.WordlistsDir,
				ContainerMode: cfg.ContainerMode,
				DockerImages:  cfg.DockerImages,
			}
			orchestrator := services.NewOrchestrator(reconConfig)
			if orchestrator != nil {
				defer orchestrator.Close()
				slog.Info("Running triggered tools on triaged targets...", "tools", triggeredTools, "targets", len(triagedTargets))
				triggeredEvents, err := orchestrator.Run(ctx, triagedTargets)
				if err != nil {
					slog.Warn("triggered tools run failed", "error", err)
				} else if len(triggeredEvents) > 0 {
					slog.Info("triggered tools completed successfully", "new_events", len(triggeredEvents))
					triagedEvents = append(triagedEvents, convertServicesEventsToRecon(triggeredEvents)...)
				}
			}
		}
	}

	return triagedEvents
}

func handleReporting(ctx context.Context, opts Options, cfg *config.Config, store *storage.Storage, normalized []string, events []recon.Event, matches []recon.Match, bridge *tui.Bridge) {
	// Wire BaselineStore for continuous monitoring
	scope := opts.Scope
	if scope == "" {
		scope = "default_run"
	}
	if bs, err := baseline.NewBaselineStore(cfg.StateDir, scope); err == nil {
		newCount := 0
		for _, ev := range events {
			isNew, _, _ := bs.AddFinding(ev.Source, ev.Type, ev.Target)
			if isNew {
				newCount++
			}
		}
		slog.Info("Baseline analysis complete", "total_events", len(events), "new_events", newCount)
		_ = bs.SaveSessionDiff()
		_ = bs.Close()
	} else {
		slog.Warn("Failed to initialize baseline store", "error", err)
	}

	insights := analyze.DeriveInsights(normalized, events)

	// Inject rule tags into insights
	for _, match := range matches {
		for i := range insights {
			if insights[i].Host == match.Event.Target || strings.Contains(match.Event.Target, insights[i].Host) {
				if match.Rule.Action.Type == "tag" {
					insights[i].Tags = append(insights[i].Tags, match.Rule.Action.Tag)
					insights[i].Reasons = append(insights[i].Reasons, match.Rule.Description)
					insights[i].Score += 10 // Bonus for rule matches
				}
			}
		}
	}

	if opts.JSONOutput {
		data, err := json.MarshalIndent(insights, "", "  ")
		if err != nil {
			slog.Error("failed to serialize insights to JSON", "error", err)
		} else {
			fmt.Println(string(data))
		}
	}

	if bridge != nil {
		for _, in := range insights {
			bridge.SendInsight(in.Host, in.Priority, in.Score)
		}
	}

	// Dispatch real-time alerts for high-priority findings
	if cfg.Notify.DiscordWebhook != "" || cfg.Notify.SlackWebhook != "" || (cfg.Notify.TelegramBotToken != "" && cfg.Notify.TelegramChatID != "") {
		notifier := utils.NewNotifier(utils.Config(notifierConfigFrom(cfg.Notify)))
		for _, in := range insights {
			if in.Priority == "high" || in.Score >= 25 {
				if err := notifier.SendAlert(ctx, utils.Finding{
					Host:     in.Host,
					Priority: in.Priority,
					Score:    in.Score,
					Tags:     in.Tags,
					Reasons:  in.Reasons,
				}); err != nil {
					slog.Warn("failed to send alert", "error", err, "host", in.Host)
				}

			}
		}
	}

	if opts.Submit {
		for _, in := range insights {
			if in.Priority == "high" || in.Score >= 25 {
				handleSubmit(opts, cfg, in)
			}
		}
	}

	// Setup global reports directory
	var globalReportDir string
	home, err := os.UserHomeDir()
	if err == nil {
		globalReportDir = filepath.Join(home, ".bbpts", "results")
		if err := os.MkdirAll(globalReportDir, 0700); err != nil {
			slog.Warn("failed to create global report directory", "dir", globalReportDir, "error", err)
		}
	}

	if opts.SummaryPath != "" {
		if err := analyze.WriteCSVSummary(opts.SummaryPath, insights); err != nil {
			slog.Error("failed to write csv summary", "path", opts.SummaryPath, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteCSVSummary(filepath.Join(globalReportDir, filepath.Base(opts.SummaryPath)), insights); err != nil {
				slog.Warn("failed to write global csv summary", "error", err)
			}
		}
	}

	if opts.ReportH1 != "" {
		if err := analyze.WriteHackerOneCSV(opts.ReportH1, insights); err != nil {
			slog.Error("failed to write HackerOne csv", "path", opts.ReportH1, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteHackerOneCSV(filepath.Join(globalReportDir, filepath.Base(opts.ReportH1)), insights); err != nil {
				slog.Warn("failed to write global HackerOne csv", "error", err)
			}
		}
	}

	if opts.ReportBC != "" {
		if err := analyze.WriteBugcrowdCSV(opts.ReportBC, insights); err != nil {
			slog.Error("failed to write Bugcrowd csv", "path", opts.ReportBC, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteBugcrowdCSV(filepath.Join(globalReportDir, filepath.Base(opts.ReportBC)), insights); err != nil {
				slog.Warn("failed to write global Bugcrowd csv", "error", err)
			}
		}
	}

	if opts.EvidencePath != "" {
		n := opts.EvidenceTopN
		if n <= 0 {
			n = 25
		}
		if err := analyze.WriteEvidenceBundle(opts.EvidencePath, insights, n); err != nil {
			slog.Error("failed to write evidence bundle", "path", opts.EvidencePath, "error", err)
		}
		if globalReportDir != "" {
			if err := analyze.WriteEvidenceBundle(filepath.Join(globalReportDir, filepath.Base(opts.EvidencePath)), insights, n); err != nil {
				slog.Warn("failed to write global evidence bundle", "error", err)
			}
		}
	}

	if opts.ObsidianDir != "" {
		if err := analyze.ExportToObsidian(opts.ObsidianDir, insights); err != nil {
			slog.Error("failed to export to obsidian", "dir", opts.ObsidianDir, "error", err)
		}
	}

	// Generate a detailed multi-format report bundle in the local results directory.
	reportDir := "results"
	if strings.TrimSpace(opts.OutputPath) != "" {
		reportDir = filepath.Dir(opts.OutputPath)
	}
	if err := os.MkdirAll(reportDir, 0700); err != nil {
		slog.Warn("failed to ensure detailed report directory", "dir", reportDir, "error", err)
		return
	}
	// Resolve custom report template path
	templatePath := opts.ReportTemplate
	if templatePath == "" {
		templatePath = cfg.ReportTemplatePath
	}

	gen := ui.NewReportGenerator(ui.ReportConfig{
		OutputPath:   reportDir,
		MarkdownPath: opts.OutputPath,
		IncludeHTML:  true,
		IncludeJSON:  true,
		IncludeBurp:  true,
		IncludeCaido: true,
		IncludeZAP:   true,
		MinimumScore: 0,
		TemplatePath: templatePath,
	})
	if err := gen.GenerateFullReport(insights, events, store); err != nil {
		slog.Warn("failed to generate detailed report bundle", "dir", reportDir, "error", err)
	}

	// Also generate in output directory
	outputDir := "output"
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		slog.Warn("failed to ensure output directory", "dir", outputDir, "error", err)
	} else {
		genOutput := ui.NewReportGenerator(ui.ReportConfig{
			OutputPath:   outputDir,
			IncludeHTML:  true,
			IncludeJSON:  true,
			IncludeBurp:  true,
			IncludeCaido: true,
			IncludeZAP:   true,
			MinimumScore: 0,
			TemplatePath: templatePath,
		})
		if err := genOutput.GenerateFullReport(insights, events, store); err != nil {
			slog.Warn("failed to generate output report bundle", "dir", outputDir, "error", err)
		}
	}

	if globalReportDir != "" {
		genGlobal := ui.NewReportGenerator(ui.ReportConfig{
			OutputPath:   globalReportDir,
			IncludeHTML:  true,
			IncludeJSON:  true,
			IncludeBurp:  true,
			IncludeCaido: true,
			IncludeZAP:   true,
			MinimumScore: 0,
			TemplatePath: templatePath,
		})
		if err := genGlobal.GenerateFullReport(insights, events, store); err != nil {
			slog.Warn("failed to generate global detailed report bundle", "dir", globalReportDir, "error", err)
		}
	}

	if store != nil && !opts.JSONOutput {
		nodes, errNodes := store.GetAllAssetNodes(0, 0)
		edges, errEdges := store.GetAllAssetEdges(0, 0)
		if errNodes == nil && errEdges == nil {
			topTargets := analyze.RecommendTargets(nodes, edges)
			if len(topTargets) > 0 {
				fmt.Println("\n=== TOP 10 INVESTIGATION TARGETS (SNIPER SCOPE) ===")
				for i, t := range topTargets {
					fmt.Printf("%d. %s\n", i+1, t.AssetID)
					fmt.Println("Why:")
					for _, w := range t.Why {
						fmt.Printf("✓ %s\n", strings.TrimPrefix(strings.TrimPrefix(w, "✓"), " "))
					}
					fmt.Printf("Score: %.0f\n\n", t.FinalScore)
				}
				fmt.Println("==================================================")
			}

			paths := analyze.GetAttackPaths(nodes, edges)
			topPaths := analyze.RankAttackPaths(paths)
			if len(topPaths) > 10 {
				topPaths = topPaths[:10]
			}
			if len(topPaths) > 0 {
				fmt.Println("\n=== TOP ATTACK PATHS ===")
				for i, p := range topPaths {
					fmt.Printf("%d. [%.0f] %s\n", i+1, p.Score, formatPathValues(p.Path, store))
				}
				fmt.Println("========================")
			}
		} else {
			slog.Warn("failed to fetch nodes/edges for sniper scope/attack path scoring", "errNodes", errNodes, "errEdges", errEdges)
		}
	}
}

func handleSubmit(opts Options, cfg *config.Config, in analyze.Insight) {
	if opts.Scope == "" {
		return
	}
	platform := strings.TrimSpace(cfg.Submit.Platform)
	if platform == "" {
		slog.Warn("submit skipped: submit.platform is not configured", "host", in.Host)
		return
	}

	title := fmt.Sprintf("High Priority Finding: %s", in.Host)
	desc := fmt.Sprintf("Host: %s\nPriority: %s\nTags: %v\n\nReasons:\n%s", in.Host, in.Priority, in.Tags, strings.Join(in.Reasons, "\n"))
	hash := submissionHash(platform, opts.Scope, in)

	if !opts.Submit {
		return
	}
	if alreadySubmitted(cfg.StateDir, hash) {
		slog.Info("submit skipped: finding already submitted", "platform", platform, "host", in.Host, "hash", hash)
		return
	}

	if err := utils.AutoSubmit(platform, opts.Scope, title, desc, "high"); err != nil {
		slog.Warn("submit failed", "platform", platform, "host", in.Host, "error", err)
		return
	}
	if err := markSubmitted(cfg.StateDir, hash); err != nil {
		slog.Warn("failed to record submit marker", "hash", hash, "error", err)
	}
}

func submissionHash(platform, scope string, in analyze.Insight) string {
	parts := []string{
		strings.ToLower(strings.TrimSpace(platform)),
		strings.ToLower(strings.TrimSpace(scope)),
		strings.ToLower(strings.TrimSpace(in.DedupeKey)),
		strings.ToLower(strings.TrimSpace(in.Host)),
		strings.Join(in.Tags, ","),
		strings.Join(in.Reasons, "\n"),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return fmt.Sprintf("%x", sum[:])
}

func submissionMarkerPath(stateDir, hash string) string {
	if strings.TrimSpace(stateDir) == "" {
		stateDir = filepath.Join(".", "results", "utils")
	}
	return filepath.Join(stateDir, "submissions", hash+".submitted")
}

func alreadySubmitted(stateDir, hash string) bool {
	_, err := os.Stat(submissionMarkerPath(stateDir, hash))
	return err == nil
}

func markSubmitted(stateDir, hash string) error {
	path := submissionMarkerPath(stateDir, hash)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0600)
}

func convertServicesEventsToRecon(events []services.Event) []recon.Event {
	out := make([]recon.Event, len(events))
	for i, ev := range events {
		out[i] = recon.Event{
			Target:     ev.Target,
			Source:     ev.Source,
			Type:       ev.Type,
			Properties: ev.Properties,
		}
	}
	return out
}

// isDirectURL reports whether the -i value looks like a URL or hostname
// that should be used as a target directly, rather than treated as a file path.
func isDirectURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Has a scheme (http://, https://) — treat as a URL target
	if strings.Contains(s, "://") {
		return true
	}
	// Bare hostname: contains at least one dot, no path separators,
	// and does not look like a common plain-file extension.
	if !strings.Contains(s, "/") && !strings.Contains(s, `\`) {
		lower := strings.ToLower(s)
		for _, ext := range fileExtsThatMightBeURLs {
			if strings.HasSuffix(lower, ext) {
				return false
			}
		}
		if strings.Contains(s, ".") {
			return true
		}
	}
	return false
}

// fileExtsThatMightBeURLs lists file extensions that should NOT be treated as
// bare URL targets. Used so that a hostname named "hostname.txt" (a file)
// isn't mistaken for a target, while "acme-corp.io" still is.
var fileExtsThatMightBeURLs = []string{
	".txt", ".csv", ".json", ".yaml", ".yml", ".xml", ".toml", ".conf",
	".log", ".jsonl", ".env", ".md", ".input",
}

func validateTargetsWithHTTPX(ctx context.Context, targets []string, threads int) ([]string, []recon.Event) {
	slog.Info("Probing input targets to verify active hosts...", "count", len(targets))

	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create a semaphore to cap parallel lookups to 50
	sem := make(chan struct{}, 50)

	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			cleanHost := target
			if strings.Contains(cleanHost, "://") {
				parts := strings.SplitN(cleanHost, "://", 2)
				cleanHost = parts[1]
			}
			if idx := strings.Index(cleanHost, "/"); idx != -1 {
				cleanHost = cleanHost[:idx]
			}
			if idx := strings.LastIndex(cleanHost, ":"); idx != -1 {
				if !(strings.Count(cleanHost, ":") > 1 && !strings.Contains(cleanHost, "]")) {
					cleanHost = cleanHost[:idx]
					cleanHost = strings.TrimPrefix(cleanHost, "[")
					cleanHost = strings.TrimSuffix(cleanHost, "]")
				}
			}

			// If it's a direct IP, it's alive
			if net.ParseIP(cleanHost) != nil {
				mu.Lock()
				alive = append(alive, target)
				mu.Unlock()
				return
			}

			// Try DNS lookup to see if it resolves
			ips, err := net.LookupIP(cleanHost)
			if err == nil && len(ips) > 0 {
				mu.Lock()
				alive = append(alive, target)
				mu.Unlock()
			} else {
				slog.Warn("Target failed DNS resolution", "target", cleanHost)
			}
		}(target)
	}
	wg.Wait()

	if len(alive) == 0 {
		slog.Warn("No targets resolved via DNS lookup.")
		return nil, nil
	}

	// Sort alive list to keep deterministic order
	sort.Strings(alive)

	httpxTool := &services.HTTPXTool{}
	events, err := httpxTool.Run(ctx, alive, threads)
	if err != nil {
		slog.Warn("Target validation via httpx failed or skipped; proceeding with DNS-resolved targets", "error", err)
		return alive, nil
	}
	if len(events) == 0 {
		slog.Warn("No targets returned active status via httpx; proceeding with DNS-resolved targets")
		return alive, nil
	}

	var validated []string
	seen := make(map[string]struct{})
	for _, ev := range events {
		targetVal := strings.TrimSpace(ev.Target)
		if targetVal != "" {
			if _, ok := seen[targetVal]; !ok {
				seen[targetVal] = struct{}{}
				validated = append(validated, targetVal)
			}
		}
	}
	slog.Info("Target validation completed successfully", "active_targets", len(validated))
	return validated, convertServicesEventsToRecon(events)
}

func formatPathValues(path []string, store *storage.Storage) string {
	if len(path) == 0 {
		return ""
	}
	if store == nil {
		return strings.Join(path, " -> ")
	}
	nodes, err := store.GetNodesByIDs(path)
	if err != nil || len(nodes) == 0 {
		return strings.Join(path, " -> ")
	}
	nodeMap := make(map[string]string)
	for _, n := range nodes {
		nodeMap[n.ID] = n.Value
	}
	var resolved []string
	for _, id := range path {
		val, exists := nodeMap[id]
		if exists {
			resolved = append(resolved, val)
		} else {
			resolved = append(resolved, id)
		}
	}
	return strings.Join(resolved, " -> ")
}
