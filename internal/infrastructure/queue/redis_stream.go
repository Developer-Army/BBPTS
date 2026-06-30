//go:build redis

package queue

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrStreamNotFound = errors.New("stream not found")
)

type RedisStreamManager struct {
	client *redis.Client
	ctx    context.Context
}

func NewRedisStreamManager(addr string) (*RedisStreamManager, error) {
	opts := &redis.Options{
		Addr:            addr,
		Password:        os.Getenv("REDIS_PASSWORD"),
		Username:        os.Getenv("REDIS_USERNAME"),
		DB:              0,
		MaxRetries:      3,
		MaxRetryBackoff: 5 * time.Second,
	}

	if os.Getenv("REDIS_USE_TLS") == "true" {
		opts.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	client := redis.NewClient(opts)

	ctx := context.Background()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisStreamManager{
		client: client,
		ctx:    ctx,
	}, nil
}

func (rsm *RedisStreamManager) EnsureStream(streamName string) error {

	info := rsm.client.XInfoStream(rsm.ctx, streamName)
	if info.Err() != nil && !errors.Is(info.Err(), redis.Nil) {
		return fmt.Errorf("failed to check stream %s: %w", streamName, info.Err())
	}

	if errors.Is(info.Err(), redis.Nil) {

		if err := rsm.client.XAdd(rsm.ctx, &redis.XAddArgs{
			Stream: streamName,
			MaxLen: 10000,
			Approx: true,
			Values: map[string]interface{}{"init": "true"},
		}).Err(); err != nil {
			return fmt.Errorf("failed to create stream %s: %w", streamName, err)
		}

		if err := rsm.client.XGroupCreate(rsm.ctx, streamName, "bbpts_group", "0").Err(); err != nil {

			if !strings.Contains(err.Error(), "BUSYGROUP") {
				return fmt.Errorf("failed to create consumer group for %s: %w", streamName, err)
			}
		}
		slog.Info("Redis stream initialized", "stream", streamName)
	}

	return nil
}

func (rsm *RedisStreamManager) PublishTask(streamName string, payload interface{}) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

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

func (rsm *RedisStreamManager) SubscribeWorker(ctx context.Context, streamName, consumerName string, handler func(data []byte) error) error {

	if err := rsm.EnsureStream(streamName); err != nil {
		return err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				slog.Info("Redis stream consumer stopped", "stream", streamName, "consumer", consumerName)
				return
			default:

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

				for _, stream := range messages {
					for _, msg := range stream.Messages {
						data, ok := msg.Values["data"].(string)
						if !ok {
							slog.Warn("Invalid message format in Redis stream", "stream", streamName, "id", msg.ID)

							rsm.client.XAck(ctx, streamName, "bbpts_group", msg.ID)
							continue
						}

						err := handler([]byte(data))
						if err != nil {
							slog.Warn("Worker task failed, will retry", "stream", streamName, "error", err)

							continue
						}

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

func (rsm *RedisStreamManager) ProcessPendingMessages(ctx context.Context, streamName, consumerName string, handler func(data []byte) error) error {

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

	for _, p := range pending {

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

				rsm.client.XAck(ctx, streamName, "bbpts_group", msg.ID)
			}
		}
	}

	return nil
}

func (rsm *RedisStreamManager) GetStreamInfo(streamName string) (map[string]interface{}, error) {
	info := rsm.client.XInfoStream(rsm.ctx, streamName)
	if info.Err() != nil {
		return nil, info.Err()
	}

	result := make(map[string]interface{})
	result["length"] = info.Val().Length
	result["groups"] = info.Val().Groups
	result["first_entry"] = info.Val().FirstEntry
	result["last_entry"] = info.Val().LastEntry

	return result, nil
}

func (rsm *RedisStreamManager) Close() error {
	return rsm.client.Close()
}
