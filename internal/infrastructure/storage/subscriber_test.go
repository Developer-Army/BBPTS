package storage

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

func TestEventSubscriber_DriftDetection(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "bbpts_subscriber_drift.db")
	s, err := NewStorage("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer s.Close()

	bus := queue.New()
	defer bus.Close()

	sub := NewEventSubscriber(s, bus)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sub.Start(ctx, []string{"subdomain", "service", "DriftEvent"})
	defer sub.Stop()

	driftSub := bus.Subscribe("DriftEvent")

	bus.Publish(queue.Event{
		Target: "test.acme.com",
		Source: "subfinder",
		Type:   "subdomain",
	})

	select {
	case ev := <-driftSub:
		if ev.Type != "DriftEvent" {
			t.Errorf("Expected DriftEvent, got %s", ev.Type)
		}
		if ev.Properties["change_type"] != "new_asset" {
			t.Errorf("Expected change_type 'new_asset', got '%s'", ev.Properties["change_type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for new_asset DriftEvent")
	}

	asset, err := s.GetAsset("test.acme.com")
	if err != nil {
		t.Fatalf("Failed to get asset: %v", err)
	}
	if asset == nil {
		t.Fatal("Expected asset to be created, got nil")
	}
	if asset.Type != "subdomain" {
		t.Errorf("Expected asset type 'subdomain', got '%s'", asset.Type)
	}

	bus.Publish(queue.Event{
		Target: "test.acme.com",
		Source: "naabu",
		Type:   "service",
	})

	select {
	case ev := <-driftSub:
		if ev.Type != "DriftEvent" {
			t.Errorf("Expected DriftEvent, got %s", ev.Type)
		}
		if ev.Properties["change_type"] != "type_change" {
			t.Errorf("Expected change_type 'type_change', got '%s'", ev.Properties["change_type"])
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for type_change DriftEvent")
	}

	asset, err = s.GetAsset("test.acme.com")
	if err != nil {
		t.Fatalf("Failed to get asset after update: %v", err)
	}
	if asset.Type != "service" {
		t.Errorf("Expected asset type updated to 'service', got '%s'", asset.Type)
	}
}
