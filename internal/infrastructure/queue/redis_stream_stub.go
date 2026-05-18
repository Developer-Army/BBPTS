//go:build !redis

package queue

import (
	"context"
	"errors"
)

type redisStreamBus struct{}

func NewRedisStreamBus(_ string) (EventBus, error) {
    return nil, errors.New("Redis support not compiled — rebuild with: go build -tags redis")
}

// RedisStreamManager stub to make sure it compiles if used
type RedisStreamManager struct{}

func NewRedisStreamManager(_ string) (*RedisStreamManager, error) {
	return nil, errors.New("Redis support not compiled — rebuild with: go build -tags redis")
}

func (rsm *RedisStreamManager) EnsureStream(streamName string) error { return errors.New("stub") }
func (rsm *RedisStreamManager) PublishTask(streamName string, payload interface{}) error { return errors.New("stub") }
func (rsm *RedisStreamManager) SubscribeWorker(ctx context.Context, streamName, consumerName string, handler func(data []byte) error) error { return errors.New("stub") }
func (rsm *RedisStreamManager) ProcessPendingMessages(ctx context.Context, streamName, consumerName string, handler func(data []byte) error) error { return errors.New("stub") }
func (rsm *RedisStreamManager) GetStreamInfo(streamName string) (map[string]interface{}, error) { return nil, errors.New("stub") }
func (rsm *RedisStreamManager) Close() error { return nil }
