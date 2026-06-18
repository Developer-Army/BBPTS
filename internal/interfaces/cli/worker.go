package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/interfaces/workers"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
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

func runWorkerNode(ctx context.Context, opts Options, cfg *config.Config) {
	_ = opts
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

func ProcessJob(ctx context.Context, ev queue.Event, eventBus queue.EventBus, cfg *config.Config) {
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
