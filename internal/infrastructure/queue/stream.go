package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

type StreamManager struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

func NewStreamManager(url string) (*StreamManager, error) {
	nc, err := nats.Connect(url, nats.RetryOnFailedConnect(true), nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to initialize JetStream: %w", err)
	}

	streamMgr := &StreamManager{
		nc: nc,
		js: js,
	}
	if err := streamMgr.EnsureStream("BBPTS_STREAM", []string{"recon.*", "scan.*", "worker.*"}); err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to ensure JetStream stream: %w", err)
	}

	return streamMgr, nil
}

func (sm *StreamManager) JetStream() nats.JetStreamContext {
	return sm.js
}

func (sm *StreamManager) EnsureStream(streamName string, subjects []string) error {
	if sm.js == nil {
		return fmt.Errorf("jetstream context is nil")
	}
	cfg := &nats.StreamConfig{
		Name:       streamName,
		Subjects:   subjects,
		Storage:    nats.FileStorage,
		MaxAge:     72 * time.Hour,
		Replicas:   1,
		Duplicates: 5 * time.Minute,
	}
	_, err := sm.js.StreamInfo(streamName)
	if err != nil {
		_, err = sm.js.AddStream(cfg)
		if err != nil {
			return fmt.Errorf("failed to create durable stream %s: %w", streamName, err)
		}
		slog.Info("Durable stream initialized", "stream", streamName)
	} else {
		_, err = sm.js.UpdateStream(cfg)
		if err != nil {
			slog.Warn("Failed to update JetStream stream configuration", "stream", streamName, "error", err)
		}
	}
	return nil
}

func (sm *StreamManager) PublishTask(subject string, payload interface{}) error {
	if payload == nil {
		return fmt.Errorf("payload cannot be nil")
	}
	if sm.js == nil {
		return fmt.Errorf("jetstream context is nil")
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	_, err = sm.js.Publish(mapSubject(subject), data)
	if err != nil {
		return fmt.Errorf("failed to publish task to %s: %w", subject, err)
	}
	return nil
}

func (sm *StreamManager) SubscribeWorker(ctx context.Context, subject, queueGroup string, handler func(data []byte) error) error {
	if handler == nil {
		return fmt.Errorf("handler cannot be nil")
	}
	if sm.js == nil {
		return fmt.Errorf("jetstream context is nil")
	}
	cb := func(msg *nats.Msg) {

		err := handler(msg.Data)
		if err != nil {
			slog.Warn("Worker task failed, NAKing for retry", "subject", subject, "error", err)
			if errNak := msg.NakWithDelay(10 * time.Second); errNak != nil {
				slog.Warn("Failed to NAK message", "error", errNak)
			}
			return
		}
		if errAck := msg.AckSync(); errAck != nil {
			slog.Warn("Failed to ACK message", "error", errAck)
		}
	}

	_, err := sm.js.QueueSubscribe(mapSubject(subject), queueGroup, cb, nats.ManualAck(), nats.MaxDeliver(3), nats.AckExplicit())
	if err != nil {
		return fmt.Errorf("failed to queue subscribe to %s: %w", subject, err)
	}

	slog.Info("Worker attached to durable stream", "subject", subject, "queue", queueGroup)
	return nil
}

func (sm *StreamManager) Close() error {
	if sm.nc != nil {
		if errDrain := sm.nc.Drain(); errDrain != nil {
			slog.Warn("Failed to drain NATS connection", "error", errDrain)
		}
		sm.nc.Close()
	}
	return nil
}

func mapSubject(subject string) string {
	if subject == "*" || subject == ">" {
		return subject
	}
	if strings.HasPrefix(subject, "recon.") || strings.HasPrefix(subject, "scan.") || strings.HasPrefix(subject, "worker.") {
		return subject
	}

	suffix := ""
	if strings.HasSuffix(subject, ".>") {
		suffix = ".>"
		subject = strings.TrimSuffix(subject, ".>")
	} else if strings.HasSuffix(subject, ".*") {
		suffix = ".*"
		subject = strings.TrimSuffix(subject, ".*")
	}

	var mapped string
	if subject == "system.worker.heartbeat" {
		mapped = "worker.heartbeat"
	} else if subject == "task.complete" {
		mapped = "worker.complete"
	} else if strings.HasPrefix(subject, "task.") {
		mapped = "worker." + strings.TrimPrefix(subject, "task.")
	} else if strings.HasPrefix(subject, "system.") {
		mapped = "worker." + strings.TrimPrefix(subject, "system.")
	} else if strings.HasPrefix(subject, "event.") {
		toolName := strings.TrimPrefix(subject, "event.")
		if toolName == "nuclei" || toolName == "dalfox" || toolName == "vuln" {
			mapped = "scan." + toolName
		} else {
			mapped = "recon." + toolName
		}
	} else {
		cleanSubject := strings.ReplaceAll(subject, ".", "_")
		mapped = "recon." + cleanSubject
	}

	return mapped + suffix
}
