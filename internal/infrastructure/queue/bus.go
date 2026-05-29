package queue

import (
	"log/slog"
	"sync"
	"time"
)

// Event represents a generic recon event. It mirrors the recon.Event struct but is kept
// lightweight for the internal bus.
type Event struct {
	Target     string            `json:"target"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties"`
	Data       []byte            `json:"data,omitempty"`
}

// Subscriber is a channel that receives events.
type Subscriber chan Event

// EventBus defines the interface for event publishing and subscribing.
type EventBus interface {
	Subscribe(eventType string) Subscriber
	QueueSubscribe(eventType, queue string) Subscriber
	Unsubscribe(ch Subscriber)
	Publish(ev Event)
	Close()
}

// InMemoryBus holds a map of event type -> list of subscriber channels.
type InMemoryBus struct {
	mu          sync.RWMutex
	subscribers map[string][]Subscriber
}

// New creates a new InMemoryBus instance.
func New() EventBus {
	return &InMemoryBus{
		subscribers: make(map[string][]Subscriber),
	}
}

// Subscribe registers a new subscriber for the given event type.
func (b *InMemoryBus) Subscribe(eventType string) Subscriber {
	return b.subscribeInternal(eventType)
}

// QueueSubscribe registers a queue subscriber (in-memory ignores queue group, behaves like normal subscribe).
func (b *InMemoryBus) QueueSubscribe(eventType, queue string) Subscriber {
	return b.subscribeInternal(eventType)
}

func (b *InMemoryBus) subscribeInternal(eventType string) Subscriber {
	ch := make(Subscriber, 128)
	b.mu.Lock()
	b.subscribers[eventType] = append(b.subscribers[eventType], ch)
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes a subscriber channel from the bus and closes it.
func (b *InMemoryBus) Unsubscribe(ch Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for eventType, subs := range b.subscribers {
		for i, sub := range subs {
			if sub == ch {
				b.subscribers[eventType] = append(subs[:i], subs[i+1:]...)
				close(ch)
				return
			}
		}
	}
}

// Publish sends an event to all matching subscribers. If a subscriber's channel is full,
// it blocks for up to 5 seconds to apply backpressure before dropping the event.
func (b *InMemoryBus) Publish(ev Event) {
	b.mu.RLock()
	subs, ok := b.subscribers[ev.Type]
	b.mu.RUnlock()
	if !ok {
		return
	}
	for _, sub := range subs {
		select {
		case sub <- ev:
		case <-time.After(5 * time.Second):
			slog.Error("event dropped: subscriber channel full after 5s backpressure timeout",
				"event_type", ev.Type,
				"target", ev.Target,
			)
		}
	}
}

// Close gracefully shuts down the bus, closing all subscriber channels.
func (b *InMemoryBus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, list := range b.subscribers {
		for _, sub := range list {
			close(sub)
		}
	}
	b.subscribers = make(map[string][]Subscriber)
}
