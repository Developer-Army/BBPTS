package storage

import (
	"context"
	"log/slog"
	"sync"

	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/assets"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

// EventSubscriber listens to an event bus and asynchronously persists events to the SQLite database.
type EventSubscriber struct {
	storage  *Storage
	bus      queue.EventBus
	done     chan struct{}
	stopOnce sync.Once
	running  bool
	mu       sync.Mutex
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
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		slog.Warn("EventSubscriber already running, ignoring Start()")
		return
	}
	s.running = true
	s.mu.Unlock()

	for _, t := range eventTypes {
		sub := s.bus.Subscribe(t)
		go s.consume(ctx, sub)
	}
}

func (s *EventSubscriber) consume(ctx context.Context, sub queue.Subscriber) {
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
			s.checkAssetDrift(reconEv)
		}
	}
}

func (s *EventSubscriber) buildGraph(ev recon.Event) {
	// Simple mapping from event types/sources to the asset graph

	// Create base target node
	targetID, err := s.storage.SaveNode("target", ev.Target, map[string]string{"source": ev.Source}, "", ev.Source, 1.0)
	if err != nil {
		slog.Debug("Failed to save graph node", "error", err)
		return
	}

	// Link active owners and teams
	owners, err := s.storage.GetAssetOwners(ev.Target)
	if err == nil {
		for _, o := range owners {
			if o.EndTime == nil {
				if o.OwnerID != nil {
					owner, err := s.storage.GetOwner(*o.OwnerID)
					if err == nil && owner != nil {
						ownerNodeID, err := s.storage.SaveNode("owner", owner.Email, map[string]string{"name": owner.Name}, "", "", 1.0)
						if err == nil {
							_ = s.storage.SaveEdge(targetID, ownerNodeID, "owned_by_owner", 1.0, "")
						}
					}
				}
				if o.TeamID != nil {
					team, err := s.storage.GetTeam(*o.TeamID)
					if err == nil && team != nil {
						teamNodeID, err := s.storage.SaveNode("team", team.Name, nil, "", "", 1.0)
						if err == nil {
							_ = s.storage.SaveEdge(targetID, teamNodeID, "owned_by_team", 1.0, "")
						}
					}
				}
			}
		}
	}

	switch ev.Source {
	case "httpx", "naabu":
		// Linking service to target
		serviceID, err := s.storage.SaveNode("service", ev.Target, ev.Properties, "", ev.Source, 1.0)
		if err != nil {
			slog.Warn("Failed to save service node", "error", err)
			return
		}
		if err := s.storage.SaveEdge(targetID, serviceID, "exposes_service", 1.0, ""); err != nil {
			slog.Warn("Failed to link target to service", "error", err)
		}
	case "nuclei", "dalfox":
		// Linking vulnerability to target
		vulnID, err := s.storage.SaveNode("vulnerability", ev.Type, ev.Properties, "", ev.Source, 1.0)
		if err != nil {
			slog.Warn("Failed to save vulnerability node", "error", err)
			return
		}
		if err := s.storage.SaveEdge(targetID, vulnID, "is_vulnerable_to", 1.0, ""); err != nil {
			slog.Warn("Failed to link target to vulnerability", "error", err)
		}
	case "graphql", "katana", "gau":
		// Linking endpoint to target
		endpointID, err := s.storage.SaveNode("endpoint", ev.Target, nil, "", ev.Source, 1.0)
		if err != nil {
			slog.Warn("Failed to save endpoint node", "error", err)
			return
		}
		if err := s.storage.SaveEdge(targetID, endpointID, "has_endpoint", 1.0, ""); err != nil {
			slog.Warn("Failed to link target to endpoint", "error", err)
		}
	}

	// Also support core event types directly (decoupled from tool names)
	switch ev.Type {
	case queue.EventHostAlive:
		serviceID, err := s.storage.SaveNode("service", ev.Target, ev.Properties, "", ev.Source, 1.0)
		if err == nil {
			_ = s.storage.SaveEdge(targetID, serviceID, "exposes_service", 1.0, "")
		}
	case queue.EventFindingCreated:
		vulnID, err := s.storage.SaveNode("vulnerability", ev.Type, ev.Properties, "", ev.Source, 1.0)
		if err == nil {
			_ = s.storage.SaveEdge(targetID, vulnID, "is_vulnerable_to", 1.0, "")
		}
	}
}

// Stop halts the subscriber.
func (s *EventSubscriber) Stop() {
	s.stopOnce.Do(func() {
		close(s.done)
	})
}

func (s *EventSubscriber) checkAssetDrift(ev recon.Event) {
	isAssetEvent := false
	switch ev.Type {
	case "subdomain", "discovery", "service", "port_open", "dns_change", "tls_change", queue.EventAssetDiscovered, queue.EventHostAlive:
		isAssetEvent = true
	}
	if !isAssetEvent {
		return
	}

	oldAsset, err := s.storage.GetAsset(ev.Target)
	if err != nil {
		slog.Debug("Failed to get asset for drift check", "error", err)
		return
	}

	var oldVal assets.Asset
	if oldAsset != nil {
		oldVal = *oldAsset
	}

	newAsset := assets.Asset{
		ID:          ev.Target,
		Type:        ev.Type,
		Name:        ev.Target,
		Criticality: "medium",
		Environment: "production",
		Confidence:  1.0,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Status:      "active",
	}

	if oldAsset != nil {
		newAsset.FirstSeen = oldAsset.FirstSeen
		newAsset.Criticality = oldAsset.Criticality
		newAsset.Environment = oldAsset.Environment
		newAsset.OwnerID = oldAsset.OwnerID
		newAsset.Confidence = oldAsset.Confidence
		newAsset.Status = oldAsset.Status
	}

	if ev.Properties != nil {
		if status, ok := ev.Properties["status"]; ok {
			newAsset.Status = status
		}
		if crit, ok := ev.Properties["criticality"]; ok {
			newAsset.Criticality = crit
		}
		if env, ok := ev.Properties["environment"]; ok {
			newAsset.Environment = env
		}
	}

	drifts := assets.DetectDrift(oldVal, newAsset)
	if len(drifts) > 0 {
		for _, d := range drifts {
			slog.Info("Drift detected!", "asset_id", d.AssetID, "change_type", d.ChangeType, "description", d.Description)
			s.bus.Publish(queue.Event{
				Target: ev.Target,
				Source: "drift_detector",
				Type:   "DriftEvent",
				Properties: map[string]string{
					"change_type": d.ChangeType,
					"old_value":   d.OldValue,
					"new_value":   d.NewValue,
					"description": d.Description,
				},
			})
		}
	}

	if err := s.storage.SaveAsset(newAsset); err != nil {
		slog.Warn("Failed to save asset in drift detector", "asset_id", newAsset.ID, "error", err)
	}
}
