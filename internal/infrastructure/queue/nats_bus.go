//go:build nats

package queue

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// NatsBus implements EventBus using NATS JetStream for guaranteed delivery.
type NatsBus struct {
	nc          *nats.Conn
	js          nats.JetStreamContext
	mu          sync.Mutex
	subscribers map[string][]*nats.Subscription
	channels    []Subscriber // To close on exit
}

// NewNatsBus creates a new NatsBus connecting to the given URL and initializes JetStream.
func NewNatsBus(url string) (EventBus, error) {
	nc, err := nats.Connect(url, nats.RetryOnFailedConnect(true), nats.MaxReconnects(10), nats.ReconnectWait(time.Second))
	if err != nil {
		return nil, err
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("failed to get jetstream context: %w", err)
	}

	// Create or update the stream for recon events
	streamName := "RECON"
	_, err = js.StreamInfo(streamName)
	if err != nil {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:     streamName,
			Subjects: []string{"*"},
			Storage:  nats.FileStorage, // Persistence
			MaxAge:   24 * time.Hour,
		})
		if err != nil {
			slog.Warn("Failed to create JetStream, falling back to core NATS behavior", "error", err)
		} else {
			slog.Info("JetStream RECON stream created successfully")
		}
	}

	return &NatsBus{
		nc:          nc,
		js:          js,
		subscribers: make(map[string][]*nats.Subscription),
	}, nil
}

// Subscribe registers a new subscriber for the given event type.
func (b *NatsBus) Subscribe(eventType string) Subscriber {
	return b.subscribeInternal(eventType, "")
}

// QueueSubscribe registers a queue subscriber for distributed worker load balancing.
func (b *NatsBus) QueueSubscribe(eventType, queue string) Subscriber {
	return b.subscribeInternal(eventType, queue)
}

func (b *NatsBus) subscribeInternal(eventType, queue string) Subscriber {
	ch := make(Subscriber, 128)
	b.mu.Lock()
	defer b.mu.Unlock()

	cb := func(m *nats.Msg) {
		var ev Event
		if err := json.Unmarshal(m.Data, &ev); err != nil {
			slog.Warn("failed to unmarshal NATS event", "error", err)
			m.Nak() // Negative Acknowledge
			return
		}

		select {
		case ch <- ev:
			m.Ack() // Acknowledge successful processing
		default:
			// Drop if full, and NAK so it redelivers
			m.Nak()
		}
	}

	var sub *nats.Subscription
	var err error
	if queue != "" {
		sub, err = b.js.QueueSubscribe(eventType, queue, cb, nats.ManualAck())
	} else {
		sub, err = b.js.Subscribe(eventType, cb, nats.ManualAck())
	}

	if err != nil {
		slog.Error("failed to subscribe to NATS JetStream", "subject", eventType, "queue", queue, "error", err)
		return ch
	}

	b.subscribers[eventType] = append(b.subscribers[eventType], sub)
	b.channels = append(b.channels, ch)
	return ch
}

// Publish publishes an event to NATS JetStream.
func (b *NatsBus) Publish(ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		slog.Error("failed to marshal event for NATS", "error", err)
		return
	}

	if _, err := b.js.Publish(ev.Type, data); err != nil {
		slog.Error("failed to publish event to NATS JetStream", "error", err)
	}
}

// Close gracefully shuts down the NATS connection.
func (b *NatsBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, subs := range b.subscribers {
		for _, sub := range subs {
			_ = sub.Unsubscribe()
		}
	}
	for _, ch := range b.channels {
		close(ch)
	}
	b.nc.Close()
}
