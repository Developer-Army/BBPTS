//go:build nats

package queue

import (
	"testing"
	"time"
)

func TestNatsBusConnectionSkip(t *testing.T) {

	bus, err := NewNatsBus("nats://127.0.0.1:4222")
	if err != nil {
		t.Skip("Skipping NATS bus tests: no local NATS server running at nats://127.0.0.1:4222")
		return
	}
	defer bus.Close()

	natsBus, ok := bus.(*NatsBus)
	if !ok {
		t.Fatal("Expected bus to be of type *NatsBus")
	}

	_, err = natsBus.js.StreamInfo("RECON")
	if err != nil {
		t.Skip("Skipping NATS bus tests: JetStream is not enabled/configured on the NATS server")
		return
	}

	t.Log("Successfully connected to local NATS server with JetStream enabled for testing")

	sub := bus.Subscribe("test-event-nats")
	if sub == nil {
		t.Fatal("Subscribe returned nil")
	}

	ev := Event{
		Type:   "test-event-nats",
		Target: "acme-corp.io",
		Source: "nats-test",
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
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for published NATS event")
	}
}
