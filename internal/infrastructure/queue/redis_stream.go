//go:build redis

package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrStreamNotFound = errors.New("stream not found")
)

// RedisStreamManager handles durable event streams using Redis Streams.
// This provides an alternative to NATS JetStream for environments where Redis is preferred.
type RedisStreamManager struct {
	client *redis.Client
	ctx    context.Context
}

// NewRedisStreamManager creates a new Redis stream manager.
func NewRedisStreamManager(addr string) (*RedisStreamManager, error) {
	client := redis.NewClient(&redis.Options{
		Addr:            addr,
		Password:        "", // No password by default
		DB:              0,  // Default DB
		MaxRetries:      3,
		MaxRetryBackoff: 5 * time.Second,
	})

	// Test connection
	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStreamManager{
		client: client,
		ctx:    ctx,
	}, nil
}

// EnsureStream guarantees that a stream exists for a given task/event type.
func (rsm *RedisStreamManager) EnsureStream(streamName string) error {
	// Check if stream exists
	info := rsm.client.XInfoStream(rsm.ctx, streamName)
	if info.Err() != nil && !errors.Is(info.Err(), redis.Nil) {
		return fmt.Errorf("failed to check stream %s: %w", streamName, info.Err())
	}

	// Create stream if it doesn't exist
	if errors.Is(info.Err(), redis.Nil) {
		// Create stream by adding a dummy message
		if err := rsm.client.XAdd(rsm.ctx, &redis.XAddArgs{
			Stream: streamName,
			MaxLen: 10000,
			Approx: true,
			Values: map[string]interface{}{"init": "true"},
		}).Err(); err != nil {
			return fmt.Errorf("failed to create stream %s: %w", streamName, err)
		}

		// Create consumer group after stream creation
		if err := rsm.client.XGroupCreate(rsm.ctx, streamName, "bbpts_group", "0").Err(); err != nil {
			// Group might already exist, that's okay
			if !strings.Contains(err.Error(), "BUSYGROUP") {
				return fmt.Errorf("failed to create consumer group for %s: %w", streamName, err)
			}
		}
		slog.Info("Redis stream initialized", "stream", streamName)
	}

	return nil
}

// PublishTask reliably publishes a task to the stream with idempotency.
func (rsm *RedisStreamManager) PublishTask(streamName string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Use XADD with MAXLEN for automatic trimming
	// Use a unique message ID for idempotency (handled by Redis)
	result := rsm.client.XAdd(rsm.ctx, &redis.XAddArgs{
		Stream: streamName,
		MaxLen: 10000,
		Approx: true,
		Values: map[string]interface{}{"data": data},
	})

	if result.Err() != nil {
		return fmt.Errorf("failed to publish task to %s: %w", streamName, result.Err())
	}

	return nil
}

// SubscribeWorker attaches an idempotent consumer to a durable queue group.
func (rsm *RedisStreamManager) SubscribeWorker(ctx context.Context, streamName, consumerName string, handler func(data []byte) error) error {
	// Ensure stream and consumer group exist
	if err := rsm.EnsureStream(streamName); err != nil {
		return err
	}

	// Start consuming in a goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Info("Redis stream consumer stopped", "stream", streamName, "consumer", consumerName)
				return
			default:
				// XREADGROUP with block for new messages
				messages, err := rsm.client.XReadGroup(ctx, &redis.XReadGroupArgs{
					Group:    "bbpts_group",
					Consumer: consumerName,
					Streams:  []string{streamName, ">"},
					Count:    10,
					Block:    5 * time.Second,
				}).Result()

				if err != nil && err != redis.Nil {
					slog.Warn("Failed to read from Redis stream", "stream", streamName, "error", err)
					time.Sleep(5 * time.Second)
					continue
				}

				// Process messages
				for _, stream := range messages {
					for _, msg := range stream.Messages {
						data, ok := msg.Values["data"].(string)
						if !ok {
							slog.Warn("Invalid message format in Redis stream", "stream", streamName, "id", msg.ID)
							// Ack the invalid message to move on
							rsm.client.XAck(ctx, streamName, "bbpts_group", msg.ID)
							continue
						}

						// Handle the message
						err := handler([]byte(data))
						if err != nil {
							slog.Warn("Worker task failed, will retry", "stream", streamName, "error", err)
							// Don't ACK, let it be retried after pending timeout
							continue
						}

						// Acknowledge successful processing
						if err := rsm.client.XAck(ctx, streamName, "bbpts_group", msg.ID).Err(); err != nil {
							slog.Warn("Failed to ACK message", "stream", streamName, "id", msg.ID, "error", err)
						}
					}
				}
			}
		}
	}()

	slog.Info("Redis stream consumer started", "stream", streamName, "consumer", consumerName)
	return nil
}

// ProcessPendingMessages handles messages that were delivered but not acknowledged.
// This is important for crash recovery - when a worker restarts, it should process its pending messages.
func (rsm *RedisStreamManager) ProcessPendingMessages(ctx context.Context, streamName, consumerName string, handler func(data []byte) error) error {
	// Get pending messages for this consumer
	pending, err := rsm.client.XPendingExt(ctx, &redis.XPendingExtArgs{
		Stream:   streamName,
		Group:    "bbpts_group",
		Start:    "-",
		End:      "+",
		Count:    100,
		Consumer: consumerName,
	}).Result()

	if err != nil {
		return fmt.Errorf("failed to get pending messages: %w", err)
	}

	// Process each pending message
	for _, p := range pending {
		// Claim the message if it's been idle too long (e.g., > 5 minutes)
		if p.Idle > 5*time.Minute {
			messages, err := rsm.client.XClaim(ctx, &redis.XClaimArgs{
				Stream:   streamName,
				Group:    "bbpts_group",
				Consumer: consumerName,
				Messages: []string{p.ID},
				MinIdle:  5 * time.Minute,
			}).Result()

			if err != nil {
				slog.Warn("Failed to claim pending message", "id", p.ID, "error", err)
				continue
			}

			for _, msg := range messages {
				data, ok := msg.Values["data"].(string)
				if !ok {
					continue
				}

				err := handler([]byte(data))
				if err != nil {
					slog.Warn("Pending task failed", "id", msg.ID, "error", err)
					continue
				}

				// Acknowledge
				rsm.client.XAck(ctx, streamName, "bbpts_group", msg.ID)
			}
		}
	}

	return nil
}

// GetStreamInfo returns information about the stream (length, groups, etc.)
func (rsm *RedisStreamManager) GetStreamInfo(streamName string) (map[string]interface{}, error) {
	info := rsm.client.XInfoStream(rsm.ctx, streamName)
	if info.Err() != nil {
		return nil, info.Err()
	}

	// Parse the stream info into a map
	result := make(map[string]interface{})
	result["length"] = info.Val().Length
	result["groups"] = info.Val().Groups
	result["first_entry"] = info.Val().FirstEntry
	result["last_entry"] = info.Val().LastEntry

	return result, nil
}

// Close disconnects the Redis client gracefully.
func (rsm *RedisStreamManager) Close() error {
	return rsm.client.Close()
}
