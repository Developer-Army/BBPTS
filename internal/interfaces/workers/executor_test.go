package workers

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewExecutor(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})

	executor := NewExecutor(worker)

	if executor == nil {
		t.Fatal("NewExecutor returned nil")
	}

	if executor.Worker != worker {
		t.Error("Expected Worker to be set")
	}

	if executor.Handlers == nil {
		t.Error("Expected Handlers map to be initialized")
	}
}

func TestNewExecutorWithNilWorker(t *testing.T) {
	executor := NewExecutor(nil)

	if executor == nil {
		t.Fatal("NewExecutor returned nil")
	}

	if executor.Worker != nil {
		t.Error("Expected Worker to be nil")
	}
}

func TestRegisterHandler(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := NewExecutor(worker)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	executor.RegisterHandler(CapSubdomainEnum, handler)

	if len(executor.Handlers) != 1 {
		t.Errorf("Expected 1 handler, got %d", len(executor.Handlers))
	}

	if _, ok := executor.Handlers[CapSubdomainEnum]; !ok {
		t.Error("Expected handler for CapSubdomainEnum to be registered")
	}
}

func TestRegisterHandlerNilHandler(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := NewExecutor(worker)

	// Should allow nil handler (though it will fail at runtime)
	executor.RegisterHandler(CapSubdomainEnum, nil)

	if len(executor.Handlers) != 1 {
		t.Errorf("Expected 1 handler, got %d", len(executor.Handlers))
	}
}

func TestRegisterHandlerOverwrite(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := NewExecutor(worker)

	handler1 := func(ctx context.Context, task Task) error {
		return nil
	}

	handler2 := func(ctx context.Context, task Task) error {
		return errors.New("error")
	}

	executor.RegisterHandler(CapSubdomainEnum, handler1)
	executor.RegisterHandler(CapSubdomainEnum, handler2)

	if len(executor.Handlers) != 1 {
		t.Errorf("Expected 1 handler (overwrite), got %d", len(executor.Handlers))
	}
}

func TestRegisterHandlerMultipleCapabilities(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum, CapPortScan})
	executor := NewExecutor(worker)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	executor.RegisterHandler(CapSubdomainEnum, handler)
	executor.RegisterHandler(CapPortScan, handler)

	if len(executor.Handlers) != 2 {
		t.Errorf("Expected 2 handlers, got %d", len(executor.Handlers))
	}
}

func TestRun(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := NewExecutor(worker)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	executor.RegisterHandler(CapSubdomainEnum, handler)

	ctx := context.Background()
	err := executor.Run(ctx)

	// Should complete without error (even if no stream is set)
	if err != nil {
		t.Errorf("Run failed: %v", err)
	}
}

func TestRunWithContextCancellation(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := NewExecutor(worker)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	executor.RegisterHandler(CapSubdomainEnum, handler)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := executor.Run(ctx)

	// Should complete without error
	if err != nil {
		t.Errorf("Run failed: %v", err)
	}
}

func TestRunWithTimeout(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := NewExecutor(worker)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	executor.RegisterHandler(CapSubdomainEnum, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := executor.Run(ctx)

	// Should complete without error
	if err != nil {
		t.Errorf("Run failed: %v", err)
	}
}

func TestRunWithoutHandlers(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := NewExecutor(worker)

	ctx := context.Background()
	err := executor.Run(ctx)

	// Should complete without error (no handlers to subscribe)
	if err != nil {
		t.Errorf("Run failed: %v", err)
	}
}

func TestRunWithNilWorker(t *testing.T) {
	executor := NewExecutor(nil)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	executor.RegisterHandler(CapSubdomainEnum, handler)

	ctx := context.Background()
	err := executor.Run(ctx)

	// Should complete without error
	if err != nil {
		t.Errorf("Run failed: %v", err)
	}
}

func TestHandlerSignature(t *testing.T) {
	// Test that handler signature matches expected type
	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	// Call the handler to verify signature
	ctx := context.Background()
	task := Task{ID: "task-123", Payload: map[string]interface{}{"key": "value"}}
	err := handler(ctx, task)

	if err != nil {
		t.Errorf("Handler failed: %v", err)
	}
}

func TestHandlerReturningError(t *testing.T) {
	handler := func(ctx context.Context, task Task) error {
		return errors.New("test error")
	}

	ctx := context.Background()
	task := Task{ID: "task-123"}
	err := handler(ctx, task)

	if err == nil {
		t.Error("Expected handler to return error")
	}

	if err.Error() != "test error" {
		t.Errorf("Expected error 'test error', got '%s'", err.Error())
	}
}

func TestHandlerWithPayload(t *testing.T) {
	handler := func(ctx context.Context, task Task) error {
		if task.Payload == nil {
			return errors.New("payload is nil")
		}
		if task.Payload["key"] != "value" {
			return errors.New("payload key mismatch")
		}
		return nil
	}

	ctx := context.Background()
	task := Task{ID: "task-123", Payload: map[string]interface{}{"key": "value"}}
	err := handler(ctx, task)

	if err != nil {
		t.Errorf("Handler failed: %v", err)
	}
}

func TestHandlerWithNilPayload(t *testing.T) {
	handler := func(ctx context.Context, task Task) error {
		if task.Payload != nil {
			return errors.New("expected nil payload")
		}
		return nil
	}

	ctx := context.Background()
	task := Task{ID: "task-123"}
	err := handler(ctx, task)

	if err != nil {
		t.Errorf("Handler failed: %v", err)
	}
}

func TestHandlerWithContext(t *testing.T) {
	handler := func(ctx context.Context, task Task) error {
		if ctx == nil {
			return errors.New("context is nil")
		}
		return nil
	}

	ctx := context.Background()
	task := Task{ID: "task-123"}
	err := handler(ctx, task)

	if err != nil {
		t.Errorf("Handler failed: %v", err)
	}
}

func TestHandlerWithCancelledContext(t *testing.T) {
	handler := func(ctx context.Context, task Task) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	task := Task{ID: "task-123"}
	err := handler(ctx, task)

	if err == nil {
		t.Error("Expected handler to return context error")
	}
}

func TestExecutorStructure(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{CapSubdomainEnum})
	executor := &Executor{
		Worker:   worker,
		Handlers: make(map[CapabilityType]TaskHandler),
	}

	if executor.Worker != worker {
		t.Error("Expected Worker to be set")
	}

	if executor.Handlers == nil {
		t.Error("Expected Handlers to be initialized")
	}
}

func TestTaskHandlerType(t *testing.T) {
	var handler TaskHandler = func(ctx context.Context, task Task) error {
		return nil
	}

	if handler == nil {
		t.Error("TaskHandler should not be nil")
	}
}

func TestRegisterHandlerForAllCapabilities(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{
		CapSubdomainEnum,
		CapPortScan,
		CapBrowserRecon,
		CapJSDiff,
	})
	executor := NewExecutor(worker)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	for _, cap := range worker.Capabilities {
		executor.RegisterHandler(cap, handler)
	}

	if len(executor.Handlers) != 4 {
		t.Errorf("Expected 4 handlers, got %d", len(executor.Handlers))
	}
}

func TestRunWithMultipleHandlers(t *testing.T) {
	worker := NewWorker("worker-1", nil, nil, []CapabilityType{
		CapSubdomainEnum,
		CapPortScan,
	})
	executor := NewExecutor(worker)

	handler := func(ctx context.Context, task Task) error {
		return nil
	}

	executor.RegisterHandler(CapSubdomainEnum, handler)
	executor.RegisterHandler(CapPortScan, handler)

	ctx := context.Background()
	err := executor.Run(ctx)

	if err != nil {
		t.Errorf("Run failed: %v", err)
	}
}
