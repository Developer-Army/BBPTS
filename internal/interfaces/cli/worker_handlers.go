package cli

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/interfaces/workers"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

// registerRealHandlers maps the distributed capability types to actual recon tools.
// This fully enables the Event-Driven Microservices architecture, removing the need
// for a central synchronous orchestrator.
func registerRealHandlers(ctx context.Context, executor *workers.Executor, cfg *config.Config) {
	// Subdomain Enumeration Handler
	executor.RegisterHandler(workers.CapSubdomainEnum, func(c context.Context, t workers.Task) error {
		slog.Info("Executing CapSubdomainEnum via Worker Mesh", "target", t.Target)
		tools := []string{"subfinder", "amass", "crtsh"}
		return executeToolsForTask(c, tools, t, cfg, executor.Worker)
	})

	// Browser Recon (Headless) Handler
	executor.RegisterHandler(workers.CapBrowserRecon, func(c context.Context, t workers.Task) error {
		slog.Info("Executing CapBrowserRecon via Worker Mesh", "target", t.Target)
		tools := []string{"browser_recon"}
		return executeToolsForTask(c, tools, t, cfg, executor.Worker)
	})

	// Port Scanning Handler
	executor.RegisterHandler(workers.CapPortScan, func(c context.Context, t workers.Task) error {
		slog.Info("Executing CapPortScan via Worker Mesh", "target", t.Target)
		tools := []string{"naabu"}
		return executeToolsForTask(c, tools, t, cfg, executor.Worker)
	})

	// JS Analysis Handler
	executor.RegisterHandler(workers.CapJSDiff, func(c context.Context, t workers.Task) error {
		slog.Info("Executing CapJSDiff via Worker Mesh", "target", t.Target)
		tools := []string{"js_analyzer"}
		return executeToolsForTask(c, tools, t, cfg, executor.Worker)
	})
}

func executeToolsForTask(ctx context.Context, toolNames []string, t workers.Task, cfg *config.Config, worker *workers.Worker) error {
	jobCtx := services.WithAPIKeys(ctx, cfg.APIKeys)
	jobCtx = services.WithWordlistsDir(jobCtx, cfg.WordlistsDir)
	jobCtx = services.WithProxies(jobCtx, cfg.Proxies)

	totalEvents := 0
	for _, name := range toolNames {
		tool, ok := services.GetToolByName(name)
		if !ok {
			slog.Warn("Tool not found in registry", "tool", name)
			continue
		}

		// Run tool independently
		events, err := tool.Run(jobCtx, []string{t.Target}, 1)
		if err != nil {
			slog.Error("Worker tool execution failed", "tool", name, "error", err)
			continue
		}

		// Publish results back to the StreamManager so other microservices can consume them
		for _, ev := range events {
			if err := publishWorkerEvent(worker, ev, t); err != nil {
				slog.Warn("Failed to publish worker event", "error", err, "source", ev.Source)
			}

			// Determine the next capability trigger based on the event type
			var nextCap workers.CapabilityType
			switch ev.Type {
			case "subdomain":
				nextCap = workers.CapPortScan
			case "port_open", "live_host":
				nextCap = workers.CapBrowserRecon
			}

			if nextCap != "" {
				nextTask := workers.Task{
					ID:        fmt.Sprintf("cascade-%s", ev.Target),
					Type:      nextCap,
					Target:    ev.Target,
					Payload:   nil,
					SessionID: t.SessionID,
				}
				_ = worker.Stream.PublishTask(fmt.Sprintf("task.%s", nextCap), nextTask)
			}
			totalEvents++
		}
	}

	_ = publishWorkerCompletion(worker, t, totalEvents, nil)
	return nil
}

func publishWorkerEvent(worker *workers.Worker, ev services.Event, task workers.Task) error {
	payload := map[string]interface{}{
		"target":     ev.Target,
		"source":     ev.Source,
		"type":       ev.Type,
		"properties": ev.Properties,
		"task_id":    task.ID,
		"session_id": task.SessionID,
	}
	return worker.Stream.PublishTask(fmt.Sprintf("event.%s", ev.Source), payload)
}

func publishWorkerCompletion(worker *workers.Worker, task workers.Task, totalEvents int, execErr error) error {
	status := "success"
	message := ""
	if execErr != nil {
		status = "failed"
		message = execErr.Error()
	}
	payload := map[string]interface{}{
		"task_id":     task.ID,
		"task_type":   task.Type,
		"target":      task.Target,
		"status":      status,
		"event_count": totalEvents,
		"session_id":  task.SessionID,
		"message":     message,
	}

	// Record task completion in idempotency store for replay
	if worker.IdempotencyMgr != nil {
		if err := worker.IdempotencyMgr.Complete(task.ID, worker.ID, status, totalEvents, nil, execErr); err != nil {
			slog.Warn("Failed to record task completion", "error", err, "task_id", task.ID)
		}
	}

	return worker.Stream.PublishTask("task.complete", payload)
}
