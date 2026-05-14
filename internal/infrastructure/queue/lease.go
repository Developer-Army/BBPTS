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

// LeaseManager implements distributed locking/leases using NATS KeyValue store.
type LeaseManager struct {
	kv nats.KeyValue
}

// NewLeaseManager creates a manager for executing exclusive tasks via leases.
func NewLeaseManager(js nats.JetStreamContext, bucketName string) (*LeaseManager, error) {
	kv, err := js.KeyValue(bucketName)
	if err != nil {
		if errors.Is(err, nats.ErrBucketNotFound) {
			kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
				Bucket:      bucketName,
				Description: "Distributed Lease Locks for BBPTS workers",
				TTL:         1 * time.Minute, // Auto-release lock if worker crashes
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

// Acquire tries to grab a lease for a specific key (e.g. target_domain).
func (lm *LeaseManager) Acquire(key, workerID string) error {
	// We use Create to ensure we only get the lock if it doesn't exist
	_, err := lm.kv.Create(key, []byte(workerID))
	if err != nil {
		return ErrLeaseUnavailable
	}
	return nil
}

// Renew updates the lease TTL, proving the worker is still alive.
func (lm *LeaseManager) Renew(key, workerID string) error {
	// Simply update the key with the same workerID to refresh the TTL
	_, err := lm.kv.Put(key, []byte(workerID))
	return err
}

// Release drops the lease, allowing others to pick it up.
func (lm *LeaseManager) Release(key string) error {
	return lm.kv.Delete(key)
}

// KeepAlive runs in the background and continuously renews the lease until the context is canceled.
func (lm *LeaseManager) KeepAlive(ctx context.Context, key, workerID string) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			lm.Release(key)
			return
		case <-ticker.C:
			if err := lm.Renew(key, workerID); err != nil {
				slog.Warn("Failed to renew lease", "key", key, "workerID", workerID, "error", err)
			}
		}
	}
}
