// Package bus implements a simple in‑process publish/subscribe event bus used by BBPTS.
package bus

import (
	"sync"
)

// Event represents a generic recon event. It mirrors the recon.Event struct but is kept
// lightweight for the internal bus.
type Event struct {
	Target     string            `json:"target"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties"`
}

// Subscriber is a channel that receives events.
type Subscriber chan Event

// Bus holds a map of event type -> list of subscriber channels.
type Bus struct {
	mu          sync.RWMutex
	subscribers map[string][]Subscriber
}

// New creates a new Bus instance.
func New() *Bus {
	return &Bus{
		subscribers: make(map[string][]Subscriber),
	}
}

// Subscribe registers a new subscriber for the given event type. The caller receives a
// read‑only channel that will receive events as they are published.
func (b *Bus) Subscribe(eventType string) Subscriber {
	ch := make(Subscriber, 128) // buffered to avoid blocking publishers
	b.mu.Lock()
	b.subscribers[eventType] = append(b.subscribers[eventType], ch)
	b.mu.Unlock()
	return ch
}

// Publish sends an event to all matching subscribers. If a subscriber's channel is full,
// the event is dropped for that subscriber to keep the pipeline flowing.
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	subs, ok := b.subscribers[ev.Type]
	b.mu.RUnlock()
	if !ok {
		return
	}
	for _, sub := range subs {
		select {
		case sub <- ev:
		default:
			// drop if subscriber is lagging – better to keep throughput high.
		}
	}
}

// Close gracefully shuts down the bus, closing all subscriber channels.
func (b *Bus) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, list := range b.subscribers {
		for _, sub := range list {
			close(sub)
		}
	}
	b.subscribers = make(map[string][]Subscriber)
}
