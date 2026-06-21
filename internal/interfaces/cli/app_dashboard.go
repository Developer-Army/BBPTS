package cli

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/server"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

// launchDashboard starts the web dashboard server in a goroutine and returns a done channel.
func launchDashboard(opts Options, cfg *config.Config) chan struct{} {
	dashboardDone := make(chan struct{})
	store, err := utils.NewStore(cfg.StateDir, true)
	if err != nil {
		slog.Error("failed to open store for dashboard", "error", err)
		close(dashboardDone)
		return dashboardDone
	}

	storeDB := store.GetDB()
	if storeDB == nil {
		close(dashboardDone)
		return dashboardDone
	}

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
		if err := server.Start(serverCfg, storeDB, opts.ConfigPath, dbSource); err != nil {
			slog.Error("dashboard server error", "error", err)
		}
	}()

	return dashboardDone
}

// waitForDashboard blocks until the dashboard server exits or user presses 'q'.
func waitForDashboard(cancel context.CancelFunc, dashboardDone chan struct{}) {
	slog.Info("dashboard is active. press 'q' or Ctrl+C to stop.")

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
				cancel()
				return
			}
		}
	}()

	<-dashboardDone
}

// runEntryPoint is the TUI/headless entry dispatcher.
func runEntryPoint(ctx context.Context, opts Options, cfg *config.Config, bridge *tui.Bridge) {
	runLoop(ctx, opts, cfg, bridge)
}
