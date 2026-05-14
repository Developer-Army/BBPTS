// Package app — app.go provides the high-level orchestration logic for BBPTS.
// Moving this out of main.go is an industry standard that makes the code
// testable and keeps the entry point clean.
package app

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/analysis/analyze"
	"github.com/Developer-Army/BBPTS/internal/analysis/wordlist"
	"github.com/Developer-Army/BBPTS/internal/core/config"
	"github.com/Developer-Army/BBPTS/internal/core/input"
	"github.com/Developer-Army/BBPTS/internal/core/normalize"
	"github.com/Developer-Army/BBPTS/internal/core/notify"
	"github.com/Developer-Army/BBPTS/internal/core/state"
	"github.com/Developer-Army/BBPTS/internal/engine/recon"
	"github.com/Developer-Army/BBPTS/internal/engine/rules"
	"github.com/Developer-Army/BBPTS/internal/ui/server"
	"github.com/Developer-Army/BBPTS/internal/ui/tui"
	tea "github.com/charmbracelet/bubbletea"
)

func notifierConfigFrom(cfg config.NotifyConfig) notify.Config {
	return notify.Config{
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
}

// Run executes the BBPTS engine with the provided options.
func Run(ctx context.Context, opts Options, cfg *config.Config, bridge *tui.Bridge, tuiProgram *tea.Program) {
	if opts.UseTUI && tuiProgram != nil {
		go func() {
			runLoop(ctx, opts, cfg, bridge)
			time.Sleep(3 * time.Second)
			tuiProgram.Send(tea.Quit())
		}()

		if _, err := tuiProgram.Run(); err != nil {
			slog.Error("BBPTS TUI error", "error", err)
			os.Exit(1)
		}
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
	var normalized []string
	var events []recon.Event
	var matches []rules.Match
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
		parser := input.NewParser()
		metadataTargets, err := parser.ParseFileWithMetadata(opts.InputPath)
		if err != nil {
			slog.Error("failed to parse input", "error", err)
			return
		}

		rawTargets := make([]string, 0, len(metadataTargets))
		for _, target := range metadataTargets {
			if !target.IsInScope() {
				continue
			}
			rawTargets = append(rawTargets, target.URL)
		}
		normalized = normalize.DeduplicateAndNormalize(rawTargets)
		if len(normalized) == 0 {
			slog.Warn("no in-scope targets were found in the input file")
			return
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
		runCtx, cancel = context.WithTimeout(ctx, opts.Timeout*time.Duration(len(toolNames)))
		defer cancel()
		runCtx = recon.WithWordlistsDir(runCtx, cfg.WordlistsDir)

		reconConfig := recon.Config{
			ToolNames:    toolNames,
			Threads:      reconThreads,
			RateLimit:    reconRateLimit,
			Proxies:      cfg.Proxies,
			APIKeys:      cfg.APIKeys,
			WordlistsDir: cfg.WordlistsDir,
			Reporter:     bridge,
			Notifier:     notify.NewNotifier(notifierConfigFrom(cfg.Notify)),
			Fleet: recon.FleetConfig{
				Enabled:     opts.EnableFleet || cfg.Fleet.Enabled,
				FleetName:   cfg.Fleet.FleetName,
				FleetSize:   cfg.Fleet.FleetSize,
				DeleteAfter: cfg.Fleet.DeleteAfter,
			},
		}

		orchestrator := recon.NewOrchestrator(reconConfig)
		defer orchestrator.Close()

		if opts.LowResource && len(normalized) > 50 {
			for i := 0; i < len(normalized); i += 20 {
				end := i + 20
				if end > len(normalized) {
					end = len(normalized)
				}
				batchEvents, err := orchestrator.Run(runCtx, normalized[i:end])
				if err != nil {
					slog.Warn("recon batch completed with tool errors", "error", err, "batch_start", i, "batch_end", end)
				}
				events = append(events, batchEvents...)
				runtime.GC()
			}
		} else {
			events, err = orchestrator.Run(runCtx, normalized)
			if err != nil {
				slog.Warn("recon completed with tool errors", "error", err)
			}
		}

		// --- Persistence & Rules ---
		ruleSet, _ := rules.LoadFromFile(opts.RulesPath)
		if ruleSet == nil {
			ruleSet = rules.DefaultRules()
		}

		matches, triggeredTools = ruleSet.Evaluate(events)
		handlePersistence(opts, cfg, normalized, events)

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
	}

	// --- Dashboard Phase ---
	var dashboardDone chan struct{}
	if opts.EnableDashboard {
		dashboardDone = make(chan struct{})
		store, err := state.NewStore(cfg.StateDir, true)
		if err != nil {
			slog.Error("failed to open store for dashboard", "error", err)
		} else {
			if db := store.GetDB(); db != nil {
				go func() {
					defer close(dashboardDone)
					if err := server.Start(server.Config{Port: opts.DashboardPort}, db); err != nil {
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

func handlePersistence(opts Options, cfg *config.Config, normalized []string, events []recon.Event) {
	if opts.Scope == "" {
		return
	}
	store, err := state.NewStore(cfg.StateDir, true)
	if err != nil {
		slog.Error("failed to open state store", "error", err)
		return
	}
	defer store.Close()

	diff, err := store.ComputeDiff(opts.Scope, normalized, events)
	if err != nil {
		slog.Warn("failed to compute diff", "error", err)
	}

	if err := store.Save(opts.Scope, normalized, events); err != nil {
		slog.Error("failed to save state", "error", err)
	}

	if diff != nil && opts.DiffOnly {
		slog.Info("diff computed", "new_targets", len(diff.NewTargets), "new_events", len(diff.NewEvents))
	}
}

func handleIntelligence(ctx context.Context, opts Options, events []recon.Event, matches []rules.Match, triggeredTools []string, threads int, bridge *tui.Bridge) {
	if len(triggeredTools) > 0 {
		slog.Info("rules triggered additional tools", "count", len(triggeredTools), "tools", triggeredTools)
		// Future: Run a second-pass orchestrator here for triggeredTools
	}
}

func handleReporting(ctx context.Context, opts Options, cfg *config.Config, normalized []string, events []recon.Event, matches []rules.Match, bridge *tui.Bridge) {
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
		notifier := notify.NewNotifier(notifierConfigFrom(cfg.Notify))
		for _, in := range insights {
			if in.Priority == "high" || in.Score >= 25 {
				if err := notifier.SendAlert(ctx, notify.Finding{
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

	// Export findings
	if opts.OutputPath != "" {
		if err := analyze.WriteMarkdownReport(opts.OutputPath, insights); err != nil {
			slog.Error("failed to write markdown report", "path", opts.OutputPath, "error", err)
		}
	}

	if opts.SummaryPath != "" {
		if err := analyze.WriteCSVSummary(opts.SummaryPath, insights); err != nil {
			slog.Error("failed to write csv summary", "path", opts.SummaryPath, "error", err)
		}
	}

	if opts.ObsidianDir != "" {
		if err := analyze.ExportToObsidian(opts.ObsidianDir, insights); err != nil {
			slog.Error("failed to export to obsidian", "dir", opts.ObsidianDir, "error", err)
		}
	}
}
