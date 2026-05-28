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
	channels    []Subscriber
	chToSub     map[Subscriber]*nats.Subscription
}

var _ func(string) (EventBus, error) = NewNatsBus

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
	cfg := &nats.StreamConfig{
		Name:     streamName,
		Subjects: []string{"recon.*", "scan.*", "worker.*"},
		Storage:  nats.FileStorage, // Persistence
		MaxAge:   24 * time.Hour,
	}
	_, err = js.StreamInfo(streamName)
	if err != nil {
		_, err = js.AddStream(cfg)
		if err != nil {
			slog.Warn("Failed to create JetStream, falling back to core NATS behavior", "error", err)
		} else {
			slog.Info("JetStream RECON stream created successfully")
		}
	} else {
		_, err = js.UpdateStream(cfg)
		if err != nil {
			slog.Warn("Failed to update JetStream stream configuration", "error", err)
		}
	}

	return &NatsBus{
		nc:          nc,
		js:          js,
		subscribers: make(map[string][]*nats.Subscription),
		chToSub:     make(map[Subscriber]*nats.Subscription),
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
			m.Nak()
			return
		}

		select {
		case ch <- ev:
			m.Ack()
		default:
			slog.Warn("event dropped: NATS subscriber channel full",
				"event_type", ev.Type,
				"target", ev.Target,
			)
			m.Nak()
		}
	}

	var sub *nats.Subscription
	var err error
	mappedSubject := mapSubject(eventType)
	if queue != "" {
		sub, err = b.js.QueueSubscribe(mappedSubject, queue, cb, nats.ManualAck())
	} else {
		sub, err = b.js.Subscribe(mappedSubject, cb, nats.ManualAck())
	}

	if err != nil {
		slog.Error("failed to subscribe to NATS JetStream", "subject", eventType, "queue", queue, "error", err)
		return ch
	}

	b.subscribers[eventType] = append(b.subscribers[eventType], sub)
	b.channels = append(b.channels, ch)
	b.chToSub[ch] = sub
	return ch
}

// Unsubscribe removes a subscriber channel and unsubscribes the NATS subscription.
func (b *NatsBus) Unsubscribe(ch Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()

	sub, ok := b.chToSub[ch]
	if ok {
		_ = sub.Unsubscribe()
		delete(b.chToSub, ch)

		// Remove from event type map
		for eventType, subs := range b.subscribers {
			for i, s := range subs {
				if s == sub {
					b.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
					break
				}
			}
		}
	}

	// Remove from channels list and close
	for i, c := range b.channels {
		if c == ch {
			b.channels = append(b.channels[:i], b.channels[i+1:]...)
			close(ch)
			return
		}
	}
}

// Publish publishes an event to NATS JetStream.
func (b *NatsBus) Publish(ev Event) {
	data, err := json.Marshal(ev)
	if err != nil {
		slog.Error("failed to marshal event for NATS", "error", err)
		return
	}

	if _, err := b.js.Publish(mapSubject(ev.Type), data); err != nil {
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
