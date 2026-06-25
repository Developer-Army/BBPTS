package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
	app "github.com/Developer-Army/BBPTS/internal/interfaces/cli"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/server"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-isatty"
)

var (
	version = "v1.4.0"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	utils.InitializeResourceGuard()
	opts := parseFlags()

	if flag.Arg(0) == "init" {
		if err := config.RunWizard(opts.ConfigPath); err != nil {
			slog.Error("wizard failed", "error", err)
			os.Exit(1)
		}
		return
	}

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

	// --- Load Config ---
	cfg, err := config.LoadFromFile(opts.ConfigPath)
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}
	cfg.LoadFromEnv()
	if opts.Headers != "" {
		if cfg.Headers == nil {
			cfg.Headers = make(map[string]string)
		}
		pairs := strings.Split(opts.Headers, ",")
		for _, pair := range pairs {
			parts := strings.SplitN(pair, ":", 2)
			if len(parts) == 2 {
				cfg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}
	if opts.Cookie != "" {
		if cfg.Headers == nil {
			cfg.Headers = make(map[string]string)
		}
		cfg.Headers["Cookie"] = opts.Cookie
	}

	// Apply web_ender / header_tag if provided
	webEnder := opts.WebEnder
	if webEnder == "" {
		webEnder = cfg.WebEnder
	}
	if webEnder != "" {
		cfg.Headers = config.ResolveWebEnder(webEnder, cfg.Headers)
	}
	app.ApplyPresetAndProfileDefaults(&opts, cfg)

	// Fallback batch size to config value if CLI flag not set
	if opts.BatchSize <= 0 && cfg.BatchSize > 1 {
		opts.BatchSize = cfg.BatchSize
	}

	// Apply CLI overrides to configuration
	if opts.FPThreshold >= 0 {
		cfg.FPConfidenceThreshold = opts.FPThreshold
	}
	if opts.IncludeFP {
		cfg.FPKeepSuppressed = true
	}
	if opts.MaxCPUPercent > 0 {
		cfg.ResourceLimits.MaxCPUPercent = opts.MaxCPUPercent
	}
	if opts.MaxCPUCores > 0 {
		cfg.ResourceLimits.MaxCPUCores = opts.MaxCPUCores
	}
	if opts.MaxMemoryMB > 0 {
		cfg.ResourceLimits.MaxMemoryMB = opts.MaxMemoryMB
	}
	if opts.GCPercent > 0 {
		cfg.ResourceLimits.GCPercent = opts.GCPercent
	}

	// Apply the resource limits
	utils.ApplyResourceLimits(
		cfg.ResourceLimits.MaxCPUPercent,
		cfg.ResourceLimits.MaxCPUCores,
		cfg.ResourceLimits.MaxMemoryMB,
		cfg.ResourceLimits.GCPercent,
	)

	// --- Logger Setup ---
	var logFile *os.File
	if opts.LogFilePath != "" {
		var err error
		logFile, err = os.OpenFile(opts.LogFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to open log file %s: %v\n", opts.LogFilePath, err)
		} else {
			defer logFile.Close()
		}
	}

	var logWriter io.Writer
	if opts.UseTUI {
		if logFile != nil {
			logWriter = logFile
		} else {
			logWriter = io.Discard
		}
	} else {
		if logFile != nil {
			logWriter = io.MultiWriter(os.Stderr, logFile)
		} else {
			logWriter = os.Stderr
		}
	}

	logWriter = &server.LogBroadcasterWriter{Original: logWriter}

	level := resolveLogLevel(opts)
	baseHandler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level})
	slog.SetDefault(slog.New(baseHandler))

	// --- TUI Setup ---
	var bridge *tui.Bridge
	var tuiProgram *tea.Program
	if opts.UseTUI {
		initialMode := app.ResolveMode(opts)
		model := tui.NewModel(initialMode, opts.ConfigPath, cfg)
		tuiProgram = tea.NewProgram(model, tea.WithAltScreen())
		bridge = tui.NewBridge(tuiProgram)

		// Redirect logs to TUI
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
		emc := telemetry.NewEnhancedMetricsCollector(15 * time.Second)
		emc.Start()
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
	flag.StringVar(&opts.OutputPath, "o", "", "Short for -output")
	flag.StringVar(&opts.SummaryPath, "summary", "", "CSV summary output path")
	flag.StringVar(&opts.SummaryPath, "s", "", "Short for -summary")
	flag.StringVar(&opts.ObsidianDir, "obsidian", "", "Obsidian note directory")
	flag.DurationVar(&opts.Timeout, "timeout", 0, "Overall recon timeout per tool group (0 disables the global timeout)")
	flag.BoolVar(&opts.Debug, "debug", false, "Enable debug logging")
	flag.IntVar(&opts.Threads, "threads", 0, "Number of concurrent threads (overrides configured default)")
	flag.StringVar(&opts.ConfigPath, "config", "", "Path to BBPTS config file")
	flag.StringVar(&opts.RulesPath, "rules", "", "Path to BBPTS rules file")
	flag.StringVar(&opts.ScopeFile, "scope-file", "", "Path to scope wildcards file")
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
	flag.BoolVar(&opts.UseTUI, "tui", true, "Enable interactive TUI dashboard")
	flag.StringVar(&opts.LogFilePath, "log-file", "bbpts.log", "Path to log file")
	flag.BoolVar(&opts.RunDoctor, "doctor", false, "Run environment diagnostics")
	flag.BoolVar(&opts.DryRun, "dry-run", false, "Dry-run mode: prints which tools would run against which targets without execution")
	flag.StringVar(&opts.AssetStore, "asset-store", "", "Path to write live JSONL asset discoveries in real time")
	flag.IntVar(&opts.CronInterval, "cron", 0, "Continuous monitoring interval (minutes)")
	flag.StringVar(&opts.ExportBurp, "export-burp", "", "Export Burp Suite XML findings")
	flag.StringVar(&opts.ReportH1, "export-h1", "", "Export HackerOne CSV format")
	flag.StringVar(&opts.ReportBC, "export-bc", "", "Export Bugcrowd CSV format")
	flag.StringVar(&opts.Headers, "H", "", "Custom HTTP headers (comma-separated, e.g. 'Key: Value, Key2: Value2')")
	flag.StringVar(&opts.Headers, "header", "", "Custom HTTP headers (comma-separated)")
	flag.StringVar(&opts.Cookie, "cookie", "", "Custom session Cookie header to inject into all HTTP-active tools")

	flag.IntVar(&opts.MaxCPUPercent, "max-cpu-percent", 0, "Max CPU percentage to use")
	flag.IntVar(&opts.MaxCPUCores, "max-cpu-cores", 0, "Max CPU cores to use (overrides percentage limit)")
	flag.IntVar(&opts.MaxMemoryMB, "max-memory-mb", 0, "Max memory limit in MB")
	flag.IntVar(&opts.GCPercent, "gc-percent", 0, "Garbage collection target percentage")

	flag.StringVar(&opts.Preset, "preset", "", "Named tool preset from config tool_presets (used when -tools is omitted)")
	flag.StringVar(&opts.Profile, "profile", "", "Named program profile from config program_profiles (exclusions + optional defaults)")
	flag.StringVar(&opts.EvidencePath, "evidence", "", "Write compact JSON evidence bundle for top insights")
	flag.IntVar(&opts.EvidenceTopN, "evidence-top", 0, "Max insights in evidence bundle (default 25)")
	flag.BoolVar(&opts.RunWorker, "worker", false, "Run as a distributed worker listening to the event bus")
	flag.BoolVar(&opts.Submit, "submit", false, "Submit high-priority findings to the configured bug bounty platform")
	flag.BoolVar(&opts.TLSEnabled, "https", false, "Start dashboard with HTTPS/TLS")
	flag.BoolVar(&opts.TLSEnabled, "tls", false, "Alias for -https")
	flag.StringVar(&opts.TLSCertFile, "tls-cert", "", "Path to TLS certificate file")
	flag.StringVar(&opts.TLSKeyFile, "tls-key", "", "Path to TLS key file")
	flag.StringVar(&opts.WebEnder, "web-ender", "", "Custom research identifier tag (e.g. H1{username})")
	flag.StringVar(&opts.WebEnder, "header-tag", "", "Alias for -web-ender")

	flag.BoolVar(&opts.DraftReport, "draft-report", false, "Draft a platform-ready markdown report using AI")
	flag.IntVar(&opts.MinimumConfidence, "min-confidence", 0, "Minimum confidence score (0-100) to include in report")
	flag.IntVar(&opts.MinimumConfidence, "c", 0, "Short for -min-confidence")
	flag.IntVar(&opts.FPThreshold, "fp-threshold", -1, "False positive confidence threshold (0-100, default from config)")
	flag.BoolVar(&opts.IncludeFP, "include-fp", false, "Include false positive/suppressed findings in the report with visual indicators")
	flag.BoolVar(&opts.FPAudit, "fp-audit", false, "Audit mode: write suppressed/false positive findings to suppressed.jsonl")
	flag.BoolVar(&opts.Resume, "resume", false, "Resume from previous checkpoint")
	flag.BoolVar(&opts.Resume, "r", false, "Short for -resume")
	flag.BoolVar(&opts.JSONOutput, "json", false, "Output results in JSON format to stdout")
	flag.BoolVar(&opts.JSONOutput, "j", false, "Short for -json")
	flag.BoolVar(&opts.AutoUpdate, "auto-update", false, "Auto-update Nuclei templates before scan")

	flag.StringVar(&opts.ExcludeTools, "exclude-tools", "", "Comma-separated tools to skip (e.g. nuclei,dalfox)")
	flag.StringVar(&opts.ExcludeTools, "x", "", "Short for -exclude-tools")
	flag.IntVar(&opts.BatchSize, "batch-size", 0, "Number of domains to scan in parallel (0 = use config or 1)")
	flag.IntVar(&opts.BatchSize, "b", 0, "Short for -batch-size")
	flag.StringVar(&opts.LogLevel, "log-level", "", "Log level: debug, info, warn, error")
	flag.StringVar(&opts.ReportTemplate, "report-template", "", "Path to custom Go text/template for HTML report")

	var showVersion bool
	flag.BoolVar(&showVersion, "version", false, "Print version information and exit")
	flag.BoolVar(&showVersion, "v", false, "Short for -version")

	flag.BoolVar(&opts.EnableMetrics, "metrics", false, "Enable Prometheus metrics endpoint")
	flag.IntVar(&opts.MetricsPort, "metrics-port", 9090, "Prometheus metrics port")
	flag.BoolVar(&opts.CI, "ci", false, "Enable CI mode with exit codes on finding discovery")
	flag.StringVar(&opts.CIFailOn, "fail-on", "medium", "Minimum severity to trigger non-zero exit code in CI mode (low, medium, high, critical)")
	flag.BoolVar(&opts.PassiveMode, "passive", false, "Passive-only stealth mode: skips active probing tools")

	reordered := reorderArgs(os.Args[1:])
	_ = flag.CommandLine.Parse(reordered)

	if opts.InputPath == "" && flag.NArg() > 0 {
		opts.InputPath = flag.Arg(0)
	}

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

	// If web/worker mode, JSON output, dry-run, or non-interactive output is used, disable TUI unless explicitly requested.
	if (opts.EnableDashboard || opts.RunWorker || opts.JSONOutput || opts.DryRun || !isatty.IsTerminal(os.Stdout.Fd())) && !tuiExplicitlySet {
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
		} else {
			home, _ := os.UserHomeDir()
			opts.RulesPath = filepath.Join(home, ".bbpts", "rules.json")
		}
	}

	if opts.InputPath == "" && !opts.EnableDashboard && !opts.RunWorker {
		if opts.UseTUI {
			// Run in TUI mode and prompt inside TUI
		} else if tuiExplicitlySet {
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

// reorderArgs moves all defined flags (and their values) to the front,
// followed by positional arguments. This allows Go's flag package to parse
// flags that are placed after positional arguments.
func reorderArgs(args []string) []string {
	var flags []string
	var posArgs []string

	i := 0
	for i < len(args) {
		arg := args[i]
		if arg == "--" {
			posArgs = append(posArgs, args[i:]...)
			break
		}
		if strings.HasPrefix(arg, "-") {
			// It is a flag
			if strings.Contains(arg, "=") {
				flags = append(flags, arg)
				i++
				continue
			}

			name := strings.TrimLeft(arg, "-")
			f := flag.Lookup(name)
			if f != nil {
				// Check if it is a boolean flag
				if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
					flags = append(flags, arg)
					i++
				} else {
					// Non-boolean flag, consumes next argument if available
					flags = append(flags, arg)
					if i+1 < len(args) {
						flags = append(flags, args[i+1])
						i += 2
					} else {
						i++
					}
				}
			} else {
				// Unknown flag, keep it in flags to let flag.Parse handle/fail on it
				flags = append(flags, arg)
				i++
			}
		} else {
			// Positional argument
			posArgs = append(posArgs, arg)
			i++
		}
	}

	return append(flags, posArgs...)
}

// resolveLogLevel maps the -log-level flag (and -debug shortcut) to slog.Level.
func resolveLogLevel(opts app.Options) slog.Level {
	if opts.LogLevel != "" {
		switch strings.ToLower(strings.TrimSpace(opts.LogLevel)) {
		case "debug":
			return slog.LevelDebug
		case "warn", "warning":
			return slog.LevelWarn
		case "error":
			return slog.LevelError
		default:
			return slog.LevelInfo
		}
	}
	if opts.Debug {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
