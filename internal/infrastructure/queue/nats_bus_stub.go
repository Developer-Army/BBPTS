//go:build !nats

package queue

import "errors"

// natsEventBus is a stub that returns a clear error when NATS is not compiled in.
type natsEventBus struct{}

func NewNatsBus(_ string) (EventBus, error) {
    return nil, errors.New("NATS support not compiled — rebuild with: go build -tags nats")
}

// Ensure exact match for what user prompted just in case:
func NewNATSBus(_ string) (EventBus, error) {
    return nil, errors.New("NATS support not compiled — rebuild with: go build -tags nats")
}
