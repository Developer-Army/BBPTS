package services

import (
	"encoding/json"
	"log/slog"
	"os"
	"time"
)

func (o *Orchestrator) reportEvent(ev Event) {
	if o.scopeGuard != nil && !o.scopeGuard.IsAllowed(ev.Target) {
		return
	}
	if reporter, ok := o.config.Reporter.(eventReporter); ok {
		reporter.ReportEvent(ev.Source, ev.Target, ev.Type, ev.Properties)
	}
	slog.Info("Discovered "+ev.Type+": "+ev.Target, "tool", ev.Source)

	if o.config.AssetStore != "" {
		o.assetStoreMu.Lock()
		defer o.assetStoreMu.Unlock()
		f, err := os.OpenFile(o.config.AssetStore, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			slog.Error("failed to open asset store file", "path", o.config.AssetStore, "error", err)
			return
		}
		defer f.Close()

		type assetRecord struct {
			Target     string            `json:"target"`
			Source     string            `json:"source"`
			Type       string            `json:"type"`
			Properties map[string]string `json:"properties,omitempty"`
			Timestamp  string            `json:"timestamp"`
		}
		rec := assetRecord{
			Target:     ev.Target,
			Source:     ev.Source,
			Type:       ev.Type,
			Properties: ev.Properties,
			Timestamp:  time.Now().UTC().Format(time.RFC3339),
		}
		data, err := json.Marshal(rec)
		if err != nil {
			slog.Error("failed to marshal asset record", "error", err)
			return
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			slog.Error("failed to write to asset store file", "path", o.config.AssetStore, "error", err)
		}
	}
}

func (o *Orchestrator) reportToolStatus(tool, status, detail string) {
	if reporter, ok := o.config.Reporter.(toolStatusReporter); ok {
		reporter.ReportToolStatus(tool, status, detail)
	}
}

func (o *Orchestrator) reportFailure(tool, detail string) {
	if reporter, ok := o.config.Reporter.(failureReporter); ok {
		reporter.ReportFailure(tool, detail)
	}
}
