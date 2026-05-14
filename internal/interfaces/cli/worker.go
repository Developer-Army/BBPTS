package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/application/services"
)

// Job defines a distributed work item for a recon tool.
type Job struct {
	ID        string   `json:"id"`
	ToolName  string   `json:"tool_name"`
	Targets   []string `json:"targets"`
	Threads   int      `json:"threads"`
	SessionID string   `json:"session_id"`
}

// RunWorker starts the distributed worker node.
func RunWorker(ctx context.Context, opts Options, cfg *config.Config) {
	runWorkerNode(ctx, opts, cfg)
}

func processJob(ctx context.Context, ev queue.Event, eventBus queue.EventBus, cfg *config.Config) {
	// Reconstruct the job from the generic event properties or payload.
	// For simplicity, we assume the job is encoded in the Properties map or we can encode it.
	var job Job
	jobData := ev.Data
	if len(jobData) == 0 {
		if raw, ok := ev.Properties["job_data"]; ok {
			jobData = []byte(raw)
		}
	}
	if len(jobData) == 0 {
		slog.Warn("Received job.recon event without job payload")
		return
	}

	if err := json.Unmarshal(jobData, &job); err != nil {
		slog.Warn("Failed to decode job data", "error", err)
		return
	}

	slog.Info("Received job", "job_id", job.ID, "tool", job.ToolName, "targets", len(job.Targets))

	tool, ok := services.GetToolByName(job.ToolName)
	if !ok {
		slog.Error("Tool not found for job", "tool", job.ToolName, "job_id", job.ID)
		return
	}

	// Prepare context with API keys and Wordlists
	jobCtx := services.WithAPIKeys(ctx, cfg.APIKeys)
	jobCtx = services.WithWordlistsDir(jobCtx, cfg.WordlistsDir)

	events, err := tool.Run(jobCtx, job.Targets, job.Threads)
	if err != nil {
		slog.Error("Job execution failed", "job_id", job.ID, "tool", job.ToolName, "error", err)
		return
	}

	slog.Info("Job completed successfully", "job_id", job.ID, "tool", job.ToolName, "events_found", len(events))

	// Publish discovered events back to the bus
	for _, resultEv := range events {
		eventBus.Publish(queue.Event{
			Target:     resultEv.Target,
			Source:     resultEv.Source,
			Type:       resultEv.Type,
			Properties: resultEv.Properties,
		})
	}

	// Publish job completion event
	eventBus.Publish(queue.Event{
		Target: "orchestrator",
		Source: "worker",
		Type:   "job.complete",
		Properties: map[string]string{
			"job_id": job.ID,
			"tool":   job.ToolName,
			"status": "success",
			"count":  fmt.Sprintf("%d", len(events)),
		},
	})
}
