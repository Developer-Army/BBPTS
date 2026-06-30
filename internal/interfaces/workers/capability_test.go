package workers

import (
	"context"
	"testing"
	"time"
)

func TestCapabilityTypeValues(t *testing.T) {
	validTypes := []CapabilityType{
		CapSubdomainEnum,
		CapPortScan,
		CapBrowserRecon,
		CapJSDiff,
	}

	expectedValues := []string{
		"subdomain_enum",
		"port_scan",
		"browser_recon",
		"js_diff",
	}

	for i, ct := range validTypes {
		if string(ct) != expectedValues[i] {
			t.Errorf("Expected capability type '%s', got '%s'", expectedValues[i], ct)
		}
	}
}

func TestNewWorker(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum, CapPortScan})

	if worker == nil {
		t.Fatal("NewWorker returned nil")
	}

	if worker.ID != "worker-1" {
		t.Errorf("Expected ID 'worker-1', got '%s'", worker.ID)
	}

	if len(worker.Capabilities) != 2 {
		t.Errorf("Expected 2 capabilities, got %d", len(worker.Capabilities))
	}

	if worker.Stream != nil {
		t.Error("Expected Stream to be nil when passed nil")
	}

	if worker.LeaseMgr != nil {
		t.Error("Expected LeaseMgr to be nil when passed nil")
	}

	if worker.IdempotencyMgr != nil {
		t.Error("Expected IdempotencyMgr to be nil by default")
	}
}

func TestNewWorkerWithNilCapabilities(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, nil)

	if worker == nil {
		t.Fatal("NewWorker returned nil")
	}

	if worker.Capabilities == nil {
		t.Error("Expected Capabilities to be initialized even when passed nil")
	}

	if len(worker.Capabilities) != 0 {
		t.Errorf("Expected 0 capabilities, got %d", len(worker.Capabilities))
	}
}

func TestNewWorkerWithEmptyCapabilities(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{})

	if worker == nil {
		t.Fatal("NewWorker returned nil")
	}

	if len(worker.Capabilities) != 0 {
		t.Errorf("Expected 0 capabilities, got %d", len(worker.Capabilities))
	}
}

func TestNewWorkerWithSingleCapability(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	if len(worker.Capabilities) != 1 {
		t.Errorf("Expected 1 capability, got %d", len(worker.Capabilities))
	}

	if worker.Capabilities[0] != CapSubdomainEnum {
		t.Errorf("Expected capability '%s', got '%s'", CapSubdomainEnum, worker.Capabilities[0])
	}
}

func TestNewWorkerWithAllCapabilities(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{
		CapSubdomainEnum,
		CapPortScan,
		CapBrowserRecon,
		CapJSDiff,
	})

	if len(worker.Capabilities) != 4 {
		t.Errorf("Expected 4 capabilities, got %d", len(worker.Capabilities))
	}
}

func TestNewWorkerWithDuplicateCapabilities(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{
		CapSubdomainEnum,
		CapSubdomainEnum,
	})

	if len(worker.Capabilities) != 2 {
		t.Errorf("Expected 2 capabilities (with duplicate), got %d", len(worker.Capabilities))
	}
}

func TestStart(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	ctx := context.Background()
	err := worker.Start(ctx)

	if err != nil {
		t.Errorf("Start failed: %v", err)
	}

	worker.mu.RLock()
	isActive := worker.isActive
	worker.mu.RUnlock()

	if !isActive {
		t.Error("Expected worker to be active after Start")
	}
}

func TestStartTwice(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	ctx := context.Background()
	err := worker.Start(ctx)
	if err != nil {
		t.Errorf("First Start failed: %v", err)
	}

	err = worker.Start(ctx)
	if err == nil {
		t.Error("Expected error when starting already active worker")
	}
}

func TestStartWithContextCancellation(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	ctx, cancel := context.WithCancel(context.Background())
	err := worker.Start(ctx)
	if err != nil {
		t.Errorf("Start failed: %v", err)
	}

	cancel()

	time.Sleep(50 * time.Millisecond)

	worker.mu.RLock()
	isActive := worker.isActive
	worker.mu.RUnlock()

	if !isActive {
		t.Error("Expected worker to remain active after context cancellation")
	}
}

func TestHeartbeat(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	go worker.heartbeat(ctx)

	time.Sleep(150 * time.Millisecond)

}

func TestHeartbeatWithNilStream(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go worker.heartbeat(ctx)

	time.Sleep(50 * time.Millisecond)
}

func TestWorkerStructure(t *testing.T) {
	worker := &Worker{
		ID:             "worker-123",
		Capabilities:   []CapabilityType{CapSubdomainEnum},
		Stream:         nil,
		LeaseMgr:       nil,
		IdempotencyMgr: nil,
		isActive:       false,
	}

	if worker.ID != "worker-123" {
		t.Errorf("Expected ID 'worker-123', got '%s'", worker.ID)
	}

	if len(worker.Capabilities) != 1 {
		t.Errorf("Expected 1 capability, got %d", len(worker.Capabilities))
	}
}

func TestWorkerMutex(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	worker.mu.Lock()
	worker.isActive = true
	worker.mu.Unlock()

	worker.mu.RLock()
	isActive := worker.isActive
	worker.mu.RUnlock()

	if !isActive {
		t.Error("Expected isActive to be true")
	}
}

func TestWorkerIDEmpty(t *testing.T) {
	worker := NewWorker("", nil, nil, []CapabilityType{CapSubdomainEnum})

	if worker.ID != "" {
		t.Errorf("Expected empty ID, got '%s'", worker.ID)
	}
}

func TestWorkerIDWithSpecialChars(t *testing.T) {
	worker := NewWorker("worker-1_special.test", nil, nil, []CapabilityType{CapSubdomainEnum})

	if worker.ID != "worker-1_special.test" {
		t.Errorf("Expected ID 'worker-1_special.test', got '%s'", worker.ID)
	}
}

func TestWorkerCapabilitiesOrder(t *testing.T) {
	caps := []CapabilityType{
		CapPortScan,
		CapSubdomainEnum,
		CapBrowserRecon,
	}

	worker := NewWorker("worker-1", nil, nil, caps)

	if len(worker.Capabilities) != 3 {
		t.Errorf("Expected 3 capabilities, got %d", len(worker.Capabilities))
	}

	if worker.Capabilities[0] != CapPortScan {
		t.Errorf("Expected first capability '%s', got '%s'", CapPortScan, worker.Capabilities[0])
	}
}

func TestWorkerWithMockStream(t *testing.T) {

	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	if worker.Stream != nil {
		t.Error("Expected Stream to be nil")
	}
}

func TestWorkerWithMockLeaseMgr(t *testing.T) {

	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	if worker.LeaseMgr != nil {
		t.Error("Expected LeaseMgr to be nil")
	}
}

func TestWorkerWithMockIdempotencyMgr(t *testing.T) {

	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	if worker.IdempotencyMgr != nil {
		t.Error("Expected IdempotencyMgr to be nil")
	}
}

func TestCapabilityTypeStringConversion(t *testing.T) {
	ct := CapSubdomainEnum

	if string(ct) != "subdomain_enum" {
		t.Errorf("Expected 'subdomain_enum', got '%s'", string(ct))
	}
}

func TestCapabilityTypeComparison(t *testing.T) {
	ct1 := CapSubdomainEnum
	ct2 := CapSubdomainEnum
	ct3 := CapPortScan

	if ct1 != ct2 {
		t.Error("Expected equal capability types to be equal")
	}

	if ct1 == ct3 {
		t.Error("Expected different capability types to not be equal")
	}
}
