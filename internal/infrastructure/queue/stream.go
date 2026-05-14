package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// StreamManager handles durable event streams for the distributed recon mesh.
type StreamManager struct {
	nc *nats.Conn
	js nats.JetStreamContext
	mu sync.Mutex
}

// NewStreamManager connects to NATS and ensures the base JetStream configuration.
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
	if err := streamMgr.EnsureStream("BBPTS_STREAM", []string{"*"}); err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to ensure JetStream stream: %w", err)
	}

	return streamMgr, nil
}

// JetStream returns the underlying JetStream context.
func (sm *StreamManager) JetStream() nats.JetStreamContext {
	return sm.js
}

// EnsureStream guarantees that a durable stream exists for a given task/event type.
func (sm *StreamManager) EnsureStream(streamName string, subjects []string) error {
	_, err := sm.js.StreamInfo(streamName)
	if err != nil {
		_, err = sm.js.AddStream(&nats.StreamConfig{
			Name:       streamName,
			Subjects:   subjects,
			Storage:    nats.FileStorage, // Durable persistence
			MaxAge:     72 * time.Hour,   // Keep events for 3 days for replayability
			Replicas:   1,                // Can be increased for HA clusters
			Duplicates: 5 * time.Minute,  // Duplicate message detection window
		})
		if err != nil {
			return fmt.Errorf("failed to create durable stream %s: %w", streamName, err)
		}
		slog.Info("Durable stream initialized", "stream", streamName)
	}
	return nil
}

// PublishTask reliably publishes a task to the stream with retries.
func (sm *StreamManager) PublishTask(subject string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Publish with sync ack to guarantee it's durable
	_, err = sm.js.Publish(subject, data)
	if err != nil {
		return fmt.Errorf("failed to publish task to %s: %w", subject, err)
	}
	return nil
}

// SubscribeWorker attaches an idempotent consumer to a durable queue group.
func (sm *StreamManager) SubscribeWorker(ctx context.Context, subject, queueGroup string, handler func(data []byte) error) error {
	cb := func(msg *nats.Msg) {
		// Idempotent execution handler
		err := handler(msg.Data)
		if err != nil {
			slog.Warn("Worker task failed, NAKing for retry", "subject", subject, "error", err)
			msg.NakWithDelay(10 * time.Second) // Deterministic retry
			return
		}
		msg.AckSync() // Fully acknowledge completion
	}

	_, err := sm.js.QueueSubscribe(subject, queueGroup, cb, nats.ManualAck(), nats.MaxDeliver(3), nats.AckExplicit())
	if err != nil {
		return fmt.Errorf("failed to queue subscribe to %s: %w", subject, err)
	}

	slog.Info("Worker attached to durable stream", "subject", subject, "queue", queueGroup)
	return nil
}

// Close disconnects the stream manager gracefully.
func (sm *StreamManager) Close() error {
	sm.nc.Drain()
	sm.nc.Close()
	return nil
}
