package storage

import (
	"context"
	"log/slog"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

// EventSubscriber listens to an event bus and asynchronously persists events to the SQLite database.
type EventSubscriber struct {
	storage *Storage
	bus     queue.EventBus
	sub     queue.Subscriber
	done    chan struct{}
}

// NewEventSubscriber creates a new background subscriber.
// It subscribes to "discovery" events and any other custom types.
func NewEventSubscriber(storage *Storage, b queue.EventBus) *EventSubscriber {
	return &EventSubscriber{
		storage: storage,
		bus:     b,
		done:    make(chan struct{}),
	}
}

// Start begins listening to the bus in a background goroutine.
func (s *EventSubscriber) Start(ctx context.Context, eventTypes []string) {
	for _, t := range eventTypes {
		sub := s.bus.Subscribe(t)
		go s.consume(ctx, sub, t)
	}
}

func (s *EventSubscriber) consume(ctx context.Context, sub queue.Subscriber, eventType string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case ev, ok := <-sub:
			if !ok {
				return // Channel closed
			}

			// Convert bus.Event back to recon.Event for storage
			reconEv := recon.Event{
				Target:     ev.Target,
				Source:     ev.Source,
				Type:       ev.Type,
				Properties: ev.Properties,
			}

			if err := s.storage.SaveEvent(reconEv); err != nil {
				slog.Warn("Failed to persist event to database", "target", ev.Target, "error", err)
			}

			s.buildGraph(reconEv)
		}
	}
}

func (s *EventSubscriber) buildGraph(ev recon.Event) {
	// Simple mapping from event types/sources to the asset graph

	// Create base target node
	targetID, err := s.storage.SaveNode("target", ev.Target, map[string]string{"source": ev.Source})
	if err != nil {
		slog.Debug("Failed to save graph node", "error", err)
		return
	}

	switch ev.Source {
	case "httpx", "naabu":
		// Linking service to target
		serviceID, _ := s.storage.SaveNode("service", ev.Target, ev.Properties)
		s.storage.SaveEdge(targetID, serviceID, "exposes_service")
	case "nuclei", "dalfox":
		// Linking vulnerability to target
		vulnID, _ := s.storage.SaveNode("vulnerability", ev.Type, ev.Properties)
		s.storage.SaveEdge(targetID, vulnID, "is_vulnerable_to")
	case "graphql", "katana", "gau":
		// Linking endpoint to target
		endpointID, _ := s.storage.SaveNode("endpoint", ev.Target, nil)
		s.storage.SaveEdge(targetID, endpointID, "has_endpoint")
	}
}

// Stop halts the subscriber.
func (s *EventSubscriber) Stop() {
	close(s.done)
}
