package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
	"github.com/Developer-Army/BBPTS/internal/interfaces/workers"
)

func (o *Orchestrator) dispatchToWorkerMesh(ctx context.Context, toolName string, targets []string, threads int) ([]Event, error) {
	jobID := fmt.Sprintf("job-%s-%d", toolName, time.Now().UnixNano())

	jobData, err := json.Marshal(map[string]interface{}{
		"id":        jobID,
		"tool_name": toolName,
		"targets":   targets,
		"threads":   threads,
	})
	if err != nil {
		return nil, err
	}

	o.bus.Publish(queue.Event{
		Target: "workers",
		Source: "orchestrator",
		Type:   "job.recon",
		Data:   jobData,
		Properties: map[string]string{
			"job_id":    jobID,
			"tool_name": toolName,
		},
	})

	sub := o.bus.Subscribe(toolName)
	completeSub := o.bus.Subscribe("job.complete")
	defer o.bus.Unsubscribe(sub)
	defer o.bus.Unsubscribe(completeSub)

	var events []Event
	timeout := o.config.Timeout
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		case <-timer.C:
			return events, fmt.Errorf("timeout waiting for worker mesh job %s", jobID)
		case ev := <-sub:
			events = append(events, Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			})
		case ev := <-completeSub:
			if ev.Properties["job_id"] == jobID {
				if ev.Properties["status"] == "success" {
					return events, nil
				}
				return events, fmt.Errorf("worker mesh job failed: %s", ev.Properties["error"])
			}
		}
	}
}

func stageCapability(stage int) workers.CapabilityType {
	switch stage {
	case 1:
		return workers.CapSubdomainEnum
	case 2:
		return workers.CapPortScan
	case 3:
		return workers.CapBrowserRecon
	case 4:
		return workers.CapJSDiff
	default:
		return ""
	}
}

func (o *Orchestrator) dispatchStageTaskToWorkerMesh(ctx context.Context, stage int, capability workers.CapabilityType, targets []string) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	completeSub := o.bus.Subscribe("task.complete")
	eventSub := o.bus.Subscribe("event.>")
	defer o.bus.Unsubscribe(completeSub)
	defer o.bus.Unsubscribe(eventSub)

	taskSession := fmt.Sprintf("stage-%d-%d", stage, time.Now().UnixNano())
	pending := len(targets)

	for _, target := range targets {
		taskID := fmt.Sprintf("stage-%d-%d", stage, time.Now().UnixNano())
		spanID := telemetry.GetSpanID(ctx)
		payload := map[string]interface{}{}
		if spanID != "" {
			payload["_trace_parent_id"] = spanID
		}
		taskPayload, err := json.Marshal(workers.Task{
			ID:        taskID,
			Type:      capability,
			Target:    target,
			Payload:   payload,
			SessionID: taskSession,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal stage task: %w", err)
		}

		o.bus.Publish(queue.Event{
			Target: target,
			Source: "orchestrator",
			Type:   fmt.Sprintf("task.%s", capability),
			Data:   taskPayload,
			Properties: map[string]string{
				"task_id":    taskID,
				"task_type":  string(capability),
				"stage":      fmt.Sprintf("%d", stage),
				"session_id": taskSession,
			},
		})
	}

	var events []Event
	timeout := o.config.Timeout
	if timeout <= 0 {
		timeout = 24 * time.Hour
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for pending > 0 {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		case <-timer.C:
			return events, fmt.Errorf("timeout waiting for stage %d completion", stage)
		case ev := <-eventSub:
			if ev.Properties["session_id"] != taskSession {
				continue
			}
			events = append(events, Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			})
		case ev := <-completeSub:
			if ev.Properties["session_id"] != taskSession {
				continue
			}
			pending--
		}
	}

	return events, nil
}
