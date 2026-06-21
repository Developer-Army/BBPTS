package cli

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	tea "github.com/charmbracelet/bubbletea"
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

	var result reconResult
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
		result = runReconPipeline(abortCtx, opts, cfg, bridge, normalized, validationEvents, reconThreads)
		store = result.store
		normalized = result.normalized
	} else {
		slog.Info("no input provided; skipping reconnaissance scan")
		if bridge != nil {
			bridge.ReportToolStatus("engine", "done", "no input; scan skipped")
		}
	}

	// --- Dashboard Phase ---
	var dashboardDone chan struct{}
	if opts.EnableDashboard {
		dashboardDone = launchDashboard(opts, cfg)
	}

	// --- Final Intelligence & Reporting ---
	events := handleIntelligence(runCtx, opts, cfg, store, result.events, result.matches, result.triggeredTools, reconThreads, bridge)

	var matches []recon.Match
	if result.matches != nil {
		matches = result.matches
	}
	handleReporting(runCtx, opts, cfg, store, normalized, events, matches, bridge)

	// If dashboard is enabled and not in cron mode, wait for it
	if opts.EnableDashboard && opts.CronInterval <= 0 && dashboardDone != nil {
		waitForDashboard(cancel, dashboardDone)
	}
}
