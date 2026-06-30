package queue

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
)

var (
	ErrLeaseUnavailable = errors.New("lease unavailable or held by another worker")
)

type LeaseManager struct {
	kv nats.KeyValue
}

func NewLeaseManager(js nats.JetStreamContext, bucketName string) (*LeaseManager, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Distributed Lease Locks for BBPTS workers",
				TTL:         1 * time.Minute,
				Storage:     nats.FileStorage,
				Replicas:    1,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create KV bucket: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to bind to KV bucket: %w", err)
		}
	}

	return &LeaseManager{kv: kv}, nil
}

func (lm *LeaseManager) Acquire(key, workerID string) error {
	if lm.kv == nil {
		return errors.New("kv store is nil")
	}

	_, err := lm.kv.Create(key, []byte(workerID))
	if err != nil {
		return ErrLeaseUnavailable
	}
	return nil
}

func (lm *LeaseManager) Renew(key, workerID string) error {
	if lm.kv == nil {
		return errors.New("kv store is nil")
	}

	_, err := lm.kv.Put(key, []byte(workerID))
	return err
}

func (lm *LeaseManager) Release(key string) error {
	if lm.kv == nil {
		return errors.New("kv store is nil")
	}
	return lm.kv.Delete(key)
}

func (lm *LeaseManager) KeepAlive(ctx context.Context, key, workerID string) {
	if lm.kv == nil {
		return
	}
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if err := lm.Release(key); err != nil {
				slog.Warn("Failed to release lease on context completion", "key", key, "error", err)
			}
			return
		case <-ticker.C:
			if err := lm.Renew(key, workerID); err != nil {
				slog.Warn("Failed to renew lease", "key", key, "workerID", workerID, "error", err)
			}
		}
	}
}
