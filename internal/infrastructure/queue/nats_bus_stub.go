//go:build !nats

package queue

import "errors"

var ErrNatsUnavailable = errors.New("nats backend not compiled; rebuild with: go build -tags nats")

var _ func(string) (EventBus, error) = NewNatsBus

func NewNatsBus(_ string) (EventBus, error) {
	return nil, ErrNatsUnavailable
}
