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
	"time"

	"github.com/Developer-Army/BBPTS/internal/app"
	"github.com/Developer-Army/BBPTS/internal/core/config"
	"github.com/Developer-Army/BBPTS/internal/core/doctor"
	"github.com/Developer-Army/BBPTS/internal/engine/recon"
	"github.com/Developer-Army/BBPTS/internal/ui/tui"
	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	opts := parseFlags()

	if opts.RunDoctor {
		results := doctor.CheckEnvironment()
		doctor.PrintReport(results)
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

	// --- Run BBPTS ---
	app.Run(ctx, opts, cfg, bridge, tuiProgram)
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
	flag.DurationVar(&opts.Timeout, "timeout", 30*time.Second, "Recon timeout per tool")
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
	flag.BoolVar(&opts.UseTUI, "tui", false, "Enable interactive TUI dashboard")
	flag.BoolVar(&opts.RunDoctor, "doctor", false, "Run environment diagnostics")
	flag.IntVar(&opts.CronInterval, "cron", 0, "Continuous monitoring interval (minutes)")
	flag.StringVar(&opts.ExportBurp, "export-burp", "", "Export Burp Suite XML findings")

	flag.Parse()

	// If no tools specified, use all available tools
	if opts.Tools == "" {
		opts.Tools = strings.Join(recon.AvailableToolNames(), ",")
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

	if opts.InputPath != "" && !opts.EnableDashboard {
		// If input is provided and web is NOT explicitly requested, default to TUI
		opts.UseTUI = true
	}

	if opts.InputPath == "" && !opts.EnableDashboard {
		// If no input and no flags, default to web mode
		fmt.Println("No input provided. Launching BBPTS Web Interface...")
		opts.EnableDashboard = true
	}

	return opts
}
