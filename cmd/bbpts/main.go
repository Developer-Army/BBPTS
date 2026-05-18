package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
	app "github.com/Developer-Army/BBPTS/internal/interfaces/cli"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	opts := parseFlags()

	if opts.ShowVersion {
		fmt.Printf("bbpts %s (commit: %s, built: %s)\n", version, commit, date)
		os.Exit(0)
	}

	if opts.RunDoctor {
		mode := app.ResolveMode(opts)
		requiredTools := strings.Split(app.ToolsetForMode(mode), ",")
		optionalTools := app.OptionalToolNamesForDoctor(mode)
		health := services.RunHealthChecksForTools(context.Background(), requiredTools, optionalTools, mode)
		fmt.Print(services.FormatHealthReport(health))
		return
	}

	// --- Signal Handling ---
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- Logger Setup ---
	if opts.Debug {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	// --- Load Config ---
	cfg, err := config.LoadFromFile(opts.ConfigPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	cfg.LoadFromEnv()
	app.ApplyPresetAndProfileDefaults(&opts, cfg)

	// --- TUI Setup ---
	var bridge *tui.Bridge
	var tuiProgram *tea.Program
	if opts.UseTUI {
		model := tui.NewModel()
		tuiProgram = tea.NewProgram(model, tea.WithAltScreen())
		bridge = tui.NewBridge(tuiProgram)

		// Redirect logs to TUI
		baseHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
		if opts.Debug {
			baseHandler = slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})
		}
		slog.SetDefault(slog.New(&tui.LogHandler{
			Handler: baseHandler,
			Program: tuiProgram,
		}))
	}

	// --- Start Telemetry ---
	if opts.EnableMetrics {
		port := fmt.Sprintf(":%d", opts.MetricsPort)
		if opts.RunWorker {
			port = fmt.Sprintf(":%d", opts.MetricsPort+1)
		}
		telemetry.StartMetricsServer(port)
		slog.Info("Prometheus metrics enabled", "addr", port)
	}

	// --- Run BBPTS ---
	if opts.RunWorker {
		app.RunWorker(ctx, opts, cfg)
	} else {
		app.Run(ctx, opts, cfg, bridge, tuiProgram)
	}
}

func parseFlags() app.Options {
	var opts app.Options

	flag.StringVar(&opts.InputPath, "input", "", "Input file path")
	flag.StringVar(&opts.InputPath, "i", "", "Short for -input")

	flag.StringVar(&opts.Tools, "tools", "", "Comma-separated recon tools to run (leave empty to run all tools)")
	flag.StringVar(&opts.Tools, "tool", "", "Comma-separated recon tools to run (short for -tools)")
	flag.StringVar(&opts.Tools, "t", "", "Comma-separated recon tools to run (short for -tools)")
	flag.StringVar(&opts.OutputPath, "output", "", "Markdown report output path")
	flag.StringVar(&opts.SummaryPath, "summary", "", "CSV summary output path")
	flag.StringVar(&opts.ObsidianDir, "obsidian", "", "Obsidian note directory")
	flag.DurationVar(&opts.Timeout, "timeout", 0, "Overall recon timeout per tool group (0 disables the global timeout)")
	flag.BoolVar(&opts.Debug, "debug", false, "Enable debug logging")
	flag.IntVar(&opts.Threads, "threads", 0, "Number of concurrent threads (overrides configured default)")
	flag.StringVar(&opts.ConfigPath, "config", "", "Path to BBPTS config file")
	flag.StringVar(&opts.RulesPath, "rules", "", "Path to BBPTS rules file")
	flag.IntVar(&opts.RateLimit, "rate-limit", 0, "Max requests/second")
	flag.StringVar(&opts.Scope, "scope", "", "Scope identifier for state tracking")
	flag.BoolVar(&opts.DiffOnly, "diff", false, "Show only new findings")

	flag.BoolVar(&opts.EnableDashboard, "web", false, "Enable local web dashboard")
	flag.BoolVar(&opts.EnableDashboard, "w", false, "Short for -web")

	flag.IntVar(&opts.DashboardPort, "port", 8080, "Dashboard port")
	flag.BoolVar(&opts.LowResource, "low-resource", false, "Optimize for weak hardware")
	flag.StringVar(&opts.Mode, "mode", "", "Scan mode: light, medium, or full (default medium)")
	flag.BoolVar(&opts.LightMode, "light", false, "Light mode: fast and low-noise core recon")
	flag.BoolVar(&opts.FullMode, "full", false, "Full mode: maximum coverage and heavier optional tools")
	flag.BoolVar(&opts.UseTUI, "tui", false, "Enable interactive TUI dashboard")
	flag.BoolVar(&opts.RunDoctor, "doctor", false, "Run environment diagnostics")
	flag.IntVar(&opts.CronInterval, "cron", 0, "Continuous monitoring interval (minutes)")
	flag.StringVar(&opts.ExportBurp, "export-burp", "", "Export Burp Suite XML findings")
	flag.StringVar(&opts.ReportH1, "export-h1", "", "Export HackerOne CSV format")
	flag.StringVar(&opts.ReportBC, "export-bc", "", "Export Bugcrowd CSV format")

	flag.StringVar(&opts.Preset, "preset", "", "Named tool preset from config tool_presets (used when -tools is omitted)")
	flag.StringVar(&opts.Profile, "profile", "", "Named program profile from config program_profiles (exclusions + optional defaults)")
	flag.StringVar(&opts.EvidencePath, "evidence", "", "Write compact JSON evidence bundle for top insights")
	flag.IntVar(&opts.EvidenceTopN, "evidence-top", 0, "Max insights in evidence bundle (default 25)")
	flag.BoolVar(&opts.RunWorker, "worker", false, "Run as a distributed worker listening to the event bus")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Log actions that would be taken without submitting reports")
	flag.BoolVar(&opts.AutoSubmit, "auto-submit", false, "Submit high-priority findings to the configured bug bounty platform")

	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Print version information and exit")
	flag.BoolVar(&showVersion, "v", false, "Short for -version")

	flag.BoolVar(&opts.EnableMetrics, "metrics", false, "Enable Prometheus metrics endpoint")
	flag.IntVar(&opts.MetricsPort, "metrics-port", 9090, "Prometheus metrics port")

	flag.Parse()

	if showVersion {
		opts.ShowVersion = true
	}

	// Check if TUI was explicitly set
	tuiExplicitlySet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "tui" {
			tuiExplicitlySet = true
		}
	})

	// If web/worker mode or non-interactive output is used, disable TUI unless explicitly requested.
	if (opts.EnableDashboard || opts.RunWorker || !isatty.IsTerminal(os.Stdout.Fd())) && !tuiExplicitlySet {
		opts.UseTUI = false
	}

	if opts.RunDoctor {
		return opts
	}

	if opts.ConfigPath == "" {
		if _, err := os.Stat(filepath.Join("configs", "config.json")); err == nil {
			opts.ConfigPath = filepath.Join("configs", "config.json")
		} else {
			home, _ := os.UserHomeDir()
			opts.ConfigPath = filepath.Join(home, ".bbpts", "config.json")
		}
	}

	if opts.RulesPath == "" {
		if _, err := os.Stat(filepath.Join("configs", "rules.json")); err == nil {
			opts.RulesPath = filepath.Join("configs", "rules.json")
		}
	}

	if opts.InputPath == "" && !opts.EnableDashboard && !opts.RunWorker {
		if !opts.UseTUI && tuiExplicitlySet {
			// --tui=false passed with no input -> Default to Worker Mode
			fmt.Println("No input and --tui=false provided. Defaulting to Worker Mode...")
			opts.RunWorker = true
		} else {
			// No input -> Default to Web Interface
			fmt.Println("No input provided. Defaulting to Web Interface...")
			opts.EnableDashboard = true
			opts.UseTUI = false
		}
	}

	return opts
}
