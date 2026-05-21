//go:build !nats

package queue

import "errors"

// ErrNatsUnavailable is returned when the NATS JetStream backend is not compiled.
var ErrNatsUnavailable = errors.New("nats backend not compiled; rebuild with: go build -tags nats")

var _ func(string) (EventBus, error) = NewNatsBus

// NewNatsBus returns ErrNatsUnavailable as NATS support is disabled in this build.
func NewNatsBus(_ string) (EventBus, error) {
	return nil, ErrNatsUnavailable
}
