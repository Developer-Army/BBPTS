package queue

import (
	"log/slog"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/telemetry"
)

const (
	EventAssetDiscovered = "AssetDiscovered"
	EventHostAlive       = "HostAlive"
	EventFindingCreated  = "FindingCreated"
	EventFindingVerified = "FindingVerified"
	EventFindingClosed   = "FindingClosed"
	EventRiskChanged     = "RiskChanged"
	EventOwnerAssigned   = "OwnerAssigned"
)

type Event struct {
	Target     string            `json:"target"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties"`
	Data       []byte            `json:"data,omitempty"`
}

type Subscriber chan Event

type EventBus interface {
	Subscribe(eventType string) Subscriber
	QueueSubscribe(eventType, queue string) Subscriber
	Unsubscribe(ch Subscriber)
	Publish(ev Event)
	Close()
}

type InMemoryBus struct {
	mu          sync.RWMutex
	subscribers map[string][]Subscriber
}

func New() EventBus {
	return &InMemoryBus{
		subscribers: make(map[string][]Subscriber),
	}
}

func (b *InMemoryBus) Subscribe(eventType string) Subscriber {
	return b.subscribeInternal(eventType)
}

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
			telemetry.QueueMessageRate.WithLabelValues(ev.Type, "in-memory", "publish").Inc()
		case <-time.After(5 * time.Second):
			slog.Error("event dropped: subscriber channel full after 5s backpressure timeout",
				"event_type", ev.Type,
				"target", ev.Target,
			)
			telemetry.QueueDroppedMessages.WithLabelValues(ev.Type, "in-memory", "timeout").Inc()
		}
	}
}

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
