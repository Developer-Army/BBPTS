package queue

import (
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	bus := New()

	if bus == nil {
		t.Fatal("New returned nil")
	}

	if bus.(*InMemoryBus).subscribers == nil {
		t.Error("Expected subscribers map to be initialized")
	}
}

func TestSubscribe(t *testing.T) {
	bus := New()

	sub := bus.Subscribe("test-event")

	if sub == nil {
		t.Fatal("Subscribe returned nil")
	}

	if cap(sub) != 128 {
		t.Errorf("Expected channel capacity 128, got %d", cap(sub))
	}
}

func TestQueueSubscribe(t *testing.T) {
	bus := New()

	sub := bus.QueueSubscribe("test-event", "test-queue")

	if sub == nil {
		t.Fatal("QueueSubscribe returned nil")
	}

	if cap(sub) != 128 {
		t.Errorf("Expected channel capacity 128, got %d", cap(sub))
	}
}

func TestPublish(t *testing.T) {
	bus := New()

	sub := bus.Subscribe("test-event")

	ev := Event{
		Type:   "test-event",
		Target: "example.com",
		Source: "test",
	}

	bus.Publish(ev)

	select {
	case received := <-sub:
		if received.Type != ev.Type {
			t.Errorf("Expected type '%s', got '%s'", ev.Type, received.Type)
		}
		if received.Target != ev.Target {
			t.Errorf("Expected target '%s', got '%s'", ev.Target, received.Target)
		}
		if received.Source != ev.Source {
			t.Errorf("Expected source '%s', got '%s'", ev.Source, received.Source)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Did not receive published event")
	}
}

func TestPublishMultipleSubscribers(t *testing.T) {
	bus := New()

	sub1 := bus.Subscribe("test-event")
	sub2 := bus.Subscribe("test-event")

	ev := Event{
		Type:   "test-event",
		Target: "example.com",
	}

	bus.Publish(ev)

	// Both subscribers should receive the event
	received1 := false
	received2 := false

	select {
	case <-sub1:
		received1 = true
	case <-time.After(100 * time.Millisecond):
	}

	select {
	case <-sub2:
		received2 = true
	case <-time.After(100 * time.Millisecond):
	}

	if !received1 {
		t.Error("Subscriber 1 did not receive event")
	}

	if !received2 {
		t.Error("Subscriber 2 did not receive event")
	}
}

func TestPublishNoSubscribers(t *testing.T) {
	bus := New()

	ev := Event{
		Type:   "test-event",
		Target: "example.com",
	}

	// Should not panic when there are no subscribers
	bus.Publish(ev)
}

func TestPublishDifferentEventTypes(t *testing.T) {
	bus := New()

	sub1 := bus.Subscribe("type1")
	sub2 := bus.Subscribe("type2")

	ev1 := Event{Type: "type1", Target: "example1.com"}
	ev2 := Event{Type: "type2", Target: "example2.com"}

	bus.Publish(ev1)
	bus.Publish(ev2)

	// sub1 should only receive type1
	select {
	case received := <-sub1:
		if received.Type != "type1" {
			t.Errorf("Expected type1, got %s", received.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("sub1 did not receive type1 event")
	}

	// sub2 should only receive type2
	select {
	case received := <-sub2:
		if received.Type != "type2" {
			t.Errorf("Expected type2, got %s", received.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("sub2 did not receive type2 event")
	}
}

func TestPublishWithProperties(t *testing.T) {
	bus := New()

	sub := bus.Subscribe("test-event")

	ev := Event{
		Type:       "test-event",
		Target:     "example.com",
		Source:     "test",
		Properties: map[string]string{"key": "value"},
		Data:       []byte("test data"),
	}

	bus.Publish(ev)

	select {
	case received := <-sub:
		if received.Properties == nil {
			t.Error("Expected properties to be set")
		}
		if received.Properties["key"] != "value" {
			t.Errorf("Expected property key 'value', got '%s'", received.Properties["key"])
		}
		if string(received.Data) != "test data" {
			t.Errorf("Expected data 'test data', got '%s'", string(received.Data))
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Did not receive published event")
	}
}

func TestClose(t *testing.T) {
	bus := New()

	sub := bus.Subscribe("test-event")

	bus.Close()

	// Channel should be closed
	select {
	case _, ok := <-sub:
		if ok {
			t.Error("Expected channel to be closed")
		}
	default:
	}
}

func TestCloseMultipleSubscribers(t *testing.T) {
	bus := New()

	sub1 := bus.Subscribe("event1")
	sub2 := bus.Subscribe("event2")
	sub3 := bus.Subscribe("event1")

	bus.Close()

	// All channels should be closed
	channels := []Subscriber{sub1, sub2, sub3}
	for _, ch := range channels {
		select {
		case _, ok := <-ch:
			if ok {
				t.Error("Expected channel to be closed")
			}
		default:
		}
	}
}

func TestPublishAfterClose(t *testing.T) {
	bus := New()

	sub := bus.Subscribe("test-event")
	bus.Close()

	ev := Event{
		Type:   "test-event",
		Target: "example.com",
	}

	// Should not panic
	bus.Publish(ev)

	// Subscriber should not receive anything
	select {
	case _, ok := <-sub:
		if ok {
			t.Error("Should not receive event after close")
		}
	case <-time.After(50 * time.Millisecond):
		// Expected
	}
}

func TestSubscribeAfterClose(t *testing.T) {
	bus := New()
	bus.Close()

	// Should still allow subscribing (but channel will be closed on next close)
	sub := bus.Subscribe("test-event")

	if sub == nil {
		t.Fatal("Subscribe returned nil after close")
	}
}

func TestEventStructure(t *testing.T) {
	ev := Event{
		Target:     "example.com",
		Source:     "subfinder",
		Type:       "subdomain",
		Properties: map[string]string{"confidence": "high"},
		Data:       []byte("binary data"),
	}

	if ev.Target != "example.com" {
		t.Errorf("Expected Target 'example.com', got '%s'", ev.Target)
	}

	if ev.Source != "subfinder" {
		t.Errorf("Expected Source 'subfinder', got '%s'", ev.Source)
	}

	if ev.Type != "subdomain" {
		t.Errorf("Expected Type 'subdomain', got '%s'", ev.Type)
	}

	if ev.Properties == nil {
		t.Error("Expected Properties to be set")
	}

	if ev.Properties["confidence"] != "high" {
		t.Errorf("Expected property 'high', got '%s'", ev.Properties["confidence"])
	}

	if string(ev.Data) != "binary data" {
		t.Errorf("Expected Data 'binary data', got '%s'", string(ev.Data))
	}
}

func TestSubscriberChannel(t *testing.T) {
	bus := New()

	sub := bus.Subscribe("test-event")

	// Verify it's a channel
	if sub == nil {
		t.Fatal("Subscriber is nil")
	}

	// Send to channel should work
	go func() {
		sub <- Event{Type: "test-event"}
	}()

	select {
	case <-sub:
		// Success
	case <-time.After(100 * time.Millisecond):
		t.Error("Could not send to subscriber channel")
	}
}

func TestPublishDropsWhenFull(t *testing.T) {
	bus := New()

	// Create a subscriber that doesn't read
	sub := bus.Subscribe("test-event")

	// Fill the buffer
	for i := 0; i < 128; i++ {
		sub <- Event{Type: "test-event"}
	}

	// Publish should not block
	ev := Event{Type: "test-event", Target: "example.com"}
	bus.Publish(ev)

	// Should complete without blocking
}

func TestMultipleEventTypes(t *testing.T) {
	bus := New()

	sub1 := bus.Subscribe("subdomain")
	sub2 := bus.Subscribe("port")
	sub3 := bus.Subscribe("endpoint")

	events := []Event{
		{Type: "subdomain", Target: "sub.example.com"},
		{Type: "port", Target: "example.com:80"},
		{Type: "endpoint", Target: "https://example.com/api"},
	}

	for _, ev := range events {
		bus.Publish(ev)
	}

	// Verify each subscriber receives only its type
	select {
	case ev := <-sub1:
		if ev.Type != "subdomain" {
			t.Errorf("Expected subdomain, got %s", ev.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("sub1 did not receive event")
	}

	select {
	case ev := <-sub2:
		if ev.Type != "port" {
			t.Errorf("Expected port, got %s", ev.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("sub2 did not receive event")
	}

	select {
	case ev := <-sub3:
		if ev.Type != "endpoint" {
			t.Errorf("Expected endpoint, got %s", ev.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("sub3 did not receive event")
	}
}
