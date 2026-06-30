//go:build !redis

package queue

import (
	"context"
	"errors"
)

var ErrRedisUnavailable = errors.New("redis backend not compiled; rebuild with: go build -tags redis")

func NewRedisStreamBus(_ string) (EventBus, error) {
	return nil, ErrRedisUnavailable
}

type RedisStreamManager struct{}

func NewRedisStreamManager(_ string) (*RedisStreamManager, error) {
	return nil, ErrRedisUnavailable
}

func (rsm *RedisStreamManager) EnsureStream(_ string) error {
	return ErrRedisUnavailable
}

func (rsm *RedisStreamManager) PublishTask(_ string, _ interface{}) error {
	return ErrRedisUnavailable
}

func (rsm *RedisStreamManager) SubscribeWorker(_ context.Context, _, _ string, _ func(data []byte) error) error {
	return ErrRedisUnavailable
}

func (rsm *RedisStreamManager) ProcessPendingMessages(_ context.Context, _, _ string, _ func(data []byte) error) error {
	return ErrRedisUnavailable
}

func (rsm *RedisStreamManager) GetStreamInfo(_ string) (map[string]interface{}, error) {
	return nil, ErrRedisUnavailable
}

func (rsm *RedisStreamManager) Close() error {
	return ErrRedisUnavailable
}
