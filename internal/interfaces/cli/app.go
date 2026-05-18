// Package cli provides CLI interface components
package cli

import (
	"bufio"
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/cluster"
	"github.com/Developer-Army/BBPTS/internal/domain/analysis/wordlist"
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
	DryRun            bool
	AutoSubmit        bool
	ShowVersion       bool
	EnableMetrics     bool
	MetricsPort       int
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
	var normalized []string
	var events []recon.Event
	var matches []recon.Match
	var triggeredTools []string

	reconThreads := cfg.Threads
	if opts.Threads > 0 {
		reconThreads = opts.Threads
	}

	// Create a default context for reporting if scan is skipped
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// --- Reconnaissance Phase ---
	if opts.InputPath != "" {
		// Accept a raw URL or hostname directly with -i, no file required.
		if isDirectURL(opts.InputPath) {
			normalized = []string{opts.InputPath}
		} else if strings.TrimSpace(opts.OutputPath) == "" && strings.TrimSpace(opts.SummaryPath) == "" {
			opts.OutputPath, opts.SummaryPath = defaultReportPaths(opts.InputPath)
			slog.Info("no report paths provided; using defaults", "output", opts.OutputPath, "summary", opts.SummaryPath)
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
		} else {
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

		// Re-initialize context with proper timeout for tools
		cancel()
		if opts.Timeout > 0 {
			runCtx, cancel = context.WithTimeout(ctx, opts.Timeout*time.Duration(len(toolNames)))
			defer cancel()
		} else {
			runCtx, cancel = context.WithCancel(ctx)
			defer cancel()
		}

		runCtx = services.WithLowResource(runCtx, opts.LowResource)

		var eventBus queue.EventBus
		if cfg.EventBus.Type == "nats" {
			if cfg.EventBus.URL == "" {
				slog.Warn("NATS event bus configured but no URL provided; falling back to in-memory bus")
				eventBus = queue.New()
			} else {
				var err error
				eventBus, err = queue.NewNatsBus(cfg.EventBus.URL)
				if err != nil {
					if cfg.Fleet.WorkerMesh {
						slog.Error("NATS event bus required for worker mesh but unavailable", "error", err)
						os.Exit(1)
					}
					slog.Warn("NATS event bus unavailable (not compiled or server unreachable); falling back to in-memory bus", "error", err)
					eventBus = queue.New()
				} else {
					defer eventBus.Close()
					slog.Info("NATS event bus enabled", "url", cfg.EventBus.URL)
				}
			}
		} else if cfg.EventBus.Type == "in-memory" || cfg.EventBus.Type == "" {
			eventBus = queue.New()
		} else {
			slog.Error("Invalid event bus type", "type", cfg.EventBus.Type)
			os.Exit(1)
		}

		reconConfig := services.Config{
			ToolNames:     toolNames,
			Threads:       reconThreads,
			RateLimit:     reconRateLimit,
			Proxies:       cfg.Proxies,
			APIKeys:       cfg.APIKeys,
			WordlistsDir:  cfg.WordlistsDir,
			TmpResultsDir: resolveTmpResultsDir(opts, cfg),
			Reporter:      bridge,
			Notifier:      utils.NewNotifier(utils.Config(notifierConfigFrom(cfg.Notify))),
			EventBus:      eventBus,
			Timeout:       scanTimeout(opts.Timeout, len(toolNames)),
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
		if dbSource == "" && dbType == "sqlite3" {
			dbSource = filepath.Join(reconConfig.TmpResultsDir, "bbpts.storage")
		}

		store, err := storage.NewStorage(dbType, dbSource)
		if err == nil {
			defer store.Close()
			sub := storage.NewEventSubscriber(store, orchestrator.Bus())
			sub.Start(runCtx, []string{
				"graphql_endpoint", "cloud_bucket_open", "secret_exposed",
				"port_open", "vulnerability", "discovery", "subdomain",
			})
			defer sub.Stop()
			slog.Info("Recon Memory enabled", "db_type", dbType, "source", dbSource)
		} else {
			slog.Warn("Failed to initialize Recon Memory storage", "error", err, "db_type", dbType)
		}

		if bridge != nil {
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
			if len(cp.TargetsPending) < len(normalized) {
				slog.Info("Resuming from previous checkpoint", "remaining", len(cp.TargetsPending))
			}
			normalized = cp.TargetsPending
		}

		if opts.LowResource && len(normalized) > 50 {
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
		} else {
			servicesEvents, err := orchestrator.Run(runCtx, normalized)
			events = convertServicesEventsToRecon(servicesEvents)
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
		if diff != nil && opts.DiffOnly {
			events = diff.NewEvents
			normalized = diff.NewTargets
			// Re-evaluate recon on the diff
			matches, triggeredTools = ruleSet.Evaluate(events)
		}

		if !opts.SkipRules && strings.Contains(opts.Tools, "ffuf") {
			gen := wordlist.NewGenerator()
			gen.ProcessEvents(events)
			wordlistScope := opts.Scope
			if wordlistScope == "" {
				wordlistScope = "default"
			}
			if customWL, err := gen.SaveCustomWordlist(wordlistScope, cfg.WordlistsDir); err == nil {
				slog.Info("smart wordlist generated", "path", customWL)
			}
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
					if err := server.Start(server.Config{Port: opts.DashboardPort}, storage); err != nil {
						slog.Error("dashboard server error", "error", err)
					}
				}()
			}
		}
	}

	// --- Final Intelligence & Reporting ---
	handleIntelligence(runCtx, opts, events, matches, triggeredTools, reconThreads, bridge)
	handleReporting(runCtx, opts, cfg, normalized, events, matches, bridge)

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

func handleIntelligence(ctx context.Context, opts Options, events []recon.Event, matches []recon.Match, triggeredTools []string, threads int, bridge *tui.Bridge) {
	slog.Info("Running Advanced Offensive Intelligence Engine")

	graph := recon.NewMemoryGraph()
	scorer := recon.NewScorer()

	// Build relationship graph from raw events
	for _, ev := range events {
		// Graph building
		node := &recon.GraphNode{
			Type:       ev.Type,
			Properties: map[string]string{"Value": ev.Target},
		}
		graph.AddNode(node)

		// If it's an HTTP endpoint, score it for high-value prioritization
		if strings.HasPrefix(ev.Target, "http") {
			score := scorer.ScoreEndpoint(ev.Target, false, "")
			if score.Score > 0 {
				slog.Info("High Value Target Prioritized", "target", ev.Target, "severity", score.Severity, "score", score.Score, "reasons", score.Justification)
			}
		}
	}

	if len(triggeredTools) > 0 {
		slog.Info("recon triggered additional tools", "count", len(triggeredTools), "tools", triggeredTools)
	}
}

func handleReporting(ctx context.Context, opts Options, cfg *config.Config, normalized []string, events []recon.Event, matches []recon.Match, bridge *tui.Bridge) {
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

	if opts.AutoSubmit || opts.DryRun {
		for _, in := range insights {
			if in.Priority == "high" || in.Score >= 25 {
				handleAutoSubmit(opts, cfg, in)
			}
		}
	}

	if opts.SummaryPath != "" {
		if err := analyze.WriteCSVSummary(opts.SummaryPath, insights); err != nil {
			slog.Error("failed to write csv summary", "path", opts.SummaryPath, "error", err)
		}
	}

	if opts.ReportH1 != "" {
		if err := analyze.WriteHackerOneCSV(opts.ReportH1, insights); err != nil {
			slog.Error("failed to write HackerOne csv", "path", opts.ReportH1, "error", err)
		}
	}

	if opts.ReportBC != "" {
		if err := analyze.WriteBugcrowdCSV(opts.ReportBC, insights); err != nil {
			slog.Error("failed to write Bugcrowd csv", "path", opts.ReportBC, "error", err)
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
	}

	if opts.ObsidianDir != "" {
		if err := analyze.ExportToObsidian(opts.ObsidianDir, insights); err != nil {
			slog.Error("failed to export to obsidian", "dir", opts.ObsidianDir, "error", err)
		}
	}

	// Generate a detailed multi-format report bundle in the results directory.
	reportDir := "results"
	if strings.TrimSpace(opts.OutputPath) != "" {
		reportDir = filepath.Dir(opts.OutputPath)
	}
	if err := os.MkdirAll(reportDir, 0700); err != nil {
		slog.Warn("failed to ensure detailed report directory", "dir", reportDir, "error", err)
		return
	}
	gen := ui.NewReportGenerator(ui.ReportConfig{
		OutputPath:   reportDir,
		IncludeHTML:  true,
		IncludeJSON:  true,
		IncludeBurp:  true,
		IncludeCaido: true,
		IncludeZAP:   true,
		MinimumScore: 0,
	})
	if err := gen.GenerateFullReport(insights, events); err != nil {
		slog.Warn("failed to generate detailed report bundle", "dir", reportDir, "error", err)
	}
}

func handleAutoSubmit(opts Options, cfg *config.Config, in analyze.Insight) {
	if opts.Scope == "" {
		return
	}
	platform := strings.TrimSpace(cfg.Submit.Platform)
	if platform == "" {
		slog.Warn("auto-submit skipped: submit.platform is not configured", "host", in.Host)
		return
	}

	title := fmt.Sprintf("High Priority Finding: %s", in.Host)
	desc := fmt.Sprintf("Host: %s\nPriority: %s\nTags: %v\n\nReasons:\n%s", in.Host, in.Priority, in.Tags, strings.Join(in.Reasons, "\n"))
	hash := submissionHash(platform, opts.Scope, in)

	if opts.DryRun {
		slog.Info("dry-run: would submit finding", "platform", platform, "program", opts.Scope, "host", in.Host, "hash", hash, "title", title)
		return
	}
	if !opts.AutoSubmit {
		return
	}
	if alreadySubmitted(cfg.StateDir, hash) {
		slog.Info("auto-submit skipped: finding already submitted", "platform", platform, "host", in.Host, "hash", hash)
		return
	}

	if err := utils.AutoSubmit(platform, opts.Scope, title, desc, "high"); err != nil {
		slog.Warn("auto-submit failed", "platform", platform, "host", in.Host, "error", err)
		return
	}
	if err := markSubmitted(cfg.StateDir, hash); err != nil {
		slog.Warn("failed to record auto-submit marker", "hash", hash, "error", err)
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
// isn't mistaken for a target, while "example.com" still is.
var fileExtsThatMightBeURLs = []string{
	".txt", ".csv", ".json", ".yaml", ".yml", ".xml", ".toml", ".conf",
	".log", ".jsonl", ".env", ".md", ".input",
}
