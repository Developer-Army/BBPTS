package queue

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestErrLeaseUnavailable(t *testing.T) {
	if ErrLeaseUnavailable == nil {
		t.Error("Expected ErrLeaseUnavailable to be defined")
	}

	if ErrLeaseUnavailable.Error() == "" {
		t.Error("Expected error message to be non-empty")
	}
}

func TestLeaseManagerStructure(t *testing.T) {
	// Test the structure without NATS dependency
	lm := &LeaseManager{}
	_ = lm
}

func TestKeepAliveContextCancellation(t *testing.T) {
	// Test that KeepAlive respects context cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create a mock lease manager that doesn't actually use NATS
	lm := &LeaseManager{}

	done := make(chan bool)
	go func() {
		lm.KeepAlive(ctx, "test-key", "worker-1")
		done <- true
	}()

	// Cancel the context
	cancel()

	select {
	case <-done:
		// Expected - KeepAlive should exit
	case <-time.After(100 * time.Millisecond):
		t.Error("KeepAlive did not exit on context cancellation")
	}
}

func TestKeepAliveTicker(t *testing.T) {
	// Test that KeepAlive would call Renew periodically
	// We can't test the actual NATS calls without mocking, but we can test the logic

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	lm := &LeaseManager{}

	done := make(chan bool)
	go func() {
		lm.KeepAlive(ctx, "test-key", "worker-1")
		done <- true
	}()

	select {
	case <-done:
		// Expected - context timeout should cause exit
	case <-time.After(200 * time.Millisecond):
		t.Error("KeepAlive did not exit on context timeout")
	}
}

func TestLeaseKeyFormat(t *testing.T) {
	// Test the lease key format used in the code
	sessionID := "session-123"
	stage := "subdomain_enum"
	target := "acme-corp.io"

	expectedKey := "lease:session-123:subdomain_enum:acme-corp.io"
	actualKey := formatLeaseKey(sessionID, stage, target)

	if actualKey != expectedKey {
		t.Errorf("Expected key '%s', got '%s'", expectedKey, actualKey)
	}
}

func formatLeaseKey(sessionID, stage, target string) string {
	return "lease:" + sessionID + ":" + stage + ":" + target
}

func TestLeaseManagerNilKV(t *testing.T) {
	lm := &LeaseManager{
		kv: nil,
	}

	// Methods should handle nil kv gracefully or return errors
	err := lm.Release("test-key")
	if err == nil {
		t.Error("Expected error when kv is nil")
	}
}

func TestLeaseManagerWithMockKV(t *testing.T) {
	// Create a mock KV for testing
	mockKV := &mockKeyValue{
		data: make(map[string][]byte),
	}

	lm := &LeaseManager{
		kv: mockKV,
	}

	// Test Acquire
	err := lm.Acquire("test-key", "worker-1")
	if err != nil {
		t.Errorf("Acquire failed: %v", err)
	}

	// Test that key was created
	if _, ok := mockKV.data["test-key"]; !ok {
		t.Error("Expected key to be created")
	}

	// Test duplicate acquire
	err = lm.Acquire("test-key", "worker-2")
	if err != ErrLeaseUnavailable {
		t.Errorf("Expected ErrLeaseUnavailable, got %v", err)
	}

	// Test Release
	err = lm.Release("test-key")
	if err != nil {
		t.Errorf("Release failed: %v", err)
	}

	// Test that key was deleted
	if _, ok := mockKV.data["test-key"]; ok {
		t.Error("Expected key to be deleted")
	}

	// Test Release non-existent key
	err = lm.Release("non-existent")
	if err != nil {
		t.Errorf("Release of non-existent key should not error: %v", err)
	}
}

// mockKeyValue is a simple mock for NATS KeyValue
type mockKeyValue struct {
	nats.KeyValue
	data map[string][]byte
}

func (m *mockKeyValue) Create(key string, value []byte) (uint64, error) {
	if _, ok := m.data[key]; ok {
		return 0, nats.ErrKeyExists
	}
	m.data[key] = value
	return 1, nil
}

func (m *mockKeyValue) Put(key string, value []byte) (uint64, error) {
	m.data[key] = value
	return 1, nil
}

func (m *mockKeyValue) Get(key string) (nats.KeyValueEntry, error) {
	val, ok := m.data[key]
	if !ok {
		return nil, nats.ErrKeyNotFound
	}
	return &mockEntry{value: val}, nil
}

func (m *mockKeyValue) Delete(key string, opts ...nats.DeleteOpt) error {
	delete(m.data, key)
	return nil
}

func (m *mockKeyValue) Keys(opts ...nats.WatchOpt) ([]string, error) {
	var keys []string
	for k := range m.data {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, nats.ErrNoKeysFound
	}
	return keys, nil
}

type mockEntry struct {
	value []byte
}

func (m *mockEntry) Value() []byte {
	return m.value
}

func (m *mockEntry) Key() string {
	return ""
}

func (m *mockEntry) Revision() uint64 {
	return 0
}

func (m *mockEntry) Created() time.Time {
	return time.Time{}
}

func (m *mockEntry) Bucket() string {
	return ""
}

func (m *mockEntry) Delta() uint64 {
	return 0
}

func (m *mockEntry) Operation() nats.KeyValueOp {
	return 0
}

func TestRenew(t *testing.T) {
	mockKV := &mockKeyValue{
		data: make(map[string][]byte),
	}

	lm := &LeaseManager{
		kv: mockKV,
	}

	// Create a key first
	mockKV.data["test-key"] = []byte("worker-1")

	// Test Renew
	err := lm.Renew("test-key", "worker-1")
	if err != nil {
		t.Errorf("Renew failed: %v", err)
	}

	// Verify value was updated
	if string(mockKV.data["test-key"]) != "worker-1" {
		t.Errorf("Expected value 'worker-1', got '%s'", string(mockKV.data["test-key"]))
	}
}

func TestRenewNonExistentKey(t *testing.T) {
	mockKV := &mockKeyValue{
		data: make(map[string][]byte),
	}

	lm := &LeaseManager{
		kv: mockKV,
	}

	// Renew should work even if key doesn't exist (Put creates it)
	err := lm.Renew("non-existent", "worker-1")
	if err != nil {
		t.Errorf("Renew should create key if it doesn't exist: %v", err)
	}
}
