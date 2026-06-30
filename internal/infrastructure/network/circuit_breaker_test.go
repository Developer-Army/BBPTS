package network

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestCircuitBreakerClosedToOpen(t *testing.T) {
	cb := NewCircuitBreaker("test-tool", CircuitBreakerConfig{
		MaxFailures:  3,
		ResetTimeout: 1 * time.Second,
	})

	if cb.State() != CircuitClosed {
		t.Fatalf("expected initial state to be closed, got %s", cb.State())
	}

	for i := 0; i < 3; i++ {
		if !cb.Allow() {
			t.Fatalf("expected Allow() to return true in closed state (attempt %d)", i)
		}
		cb.RecordFailure()
	}

	if cb.State() != CircuitOpen {
		t.Fatalf("expected state to be open after %d failures, got %s", 3, cb.State())
	}

	if cb.Allow() {
		t.Fatal("expected Allow() to return false in open state")
	}
}

func TestCircuitBreakerOpenToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker("test-tool", CircuitBreakerConfig{
		MaxFailures:         2,
		ResetTimeout:        50 * time.Millisecond,
		HalfOpenMaxRequests: 2,
		SuccessThreshold:    1,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("expected open state, got %s", cb.State())
	}

	time.Sleep(60 * time.Millisecond)

	if !cb.Allow() {
		t.Fatal("expected Allow() to return true after reset timeout")
	}
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("expected half-open state, got %s", cb.State())
	}

	cb.RecordSuccess()
	if cb.State() != CircuitClosed {
		t.Fatalf("expected closed state after success in half-open, got %s", cb.State())
	}
}

func TestCircuitBreakerHalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker("test-tool", CircuitBreakerConfig{
		MaxFailures:         1,
		ResetTimeout:        50 * time.Millisecond,
		HalfOpenMaxRequests: 2,
		SuccessThreshold:    2,
	})

	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("expected open state, got %s", cb.State())
	}

	time.Sleep(60 * time.Millisecond)

	cb.Allow()
	if cb.State() != CircuitHalfOpen {
		t.Fatalf("expected half-open state, got %s", cb.State())
	}

	cb.RecordFailure()
	if cb.State() != CircuitOpen {
		t.Fatalf("expected open state after failure in half-open, got %s", cb.State())
	}
}

func TestCircuitBreakerSuccessResetsClosed(t *testing.T) {
	cb := NewCircuitBreaker("test-tool", CircuitBreakerConfig{
		MaxFailures: 3,
	})

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitClosed {
		t.Fatalf("expected closed state with 2 failures, got %s", cb.State())
	}

	cb.RecordSuccess()

	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CircuitClosed {
		t.Fatalf("expected closed state after reset + 2 failures, got %s", cb.State())
	}
}

func TestCircuitBreakerRegistry(t *testing.T) {
	reg := NewCircuitBreakerRegistry(DefaultCircuitBreakerConfig())

	cb1 := reg.Get("subfinder")
	cb2 := reg.Get("httpx")
	cb3 := reg.Get("subfinder")

	if cb1 != cb3 {
		t.Fatal("expected Get to return the same instance for the same name")
	}
	if cb1 == cb2 {
		t.Fatal("expected different instances for different names")
	}

	stats := reg.AllStats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 entries in stats, got %d", len(stats))
	}
}

func TestExecuteWithCircuitBreaker(t *testing.T) {
	cb := NewCircuitBreaker("exec-test", CircuitBreakerConfig{
		MaxFailures:  2,
		ResetTimeout: 1 * time.Second,
	})

	err := Execute(cb, func() error {
		return nil
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if cb.State() != CircuitClosed {
		t.Fatalf("expected closed state, got %s", cb.State())
	}
}

func TestCircuitBreakerStateChangeCallback(t *testing.T) {
	var called int32 = 0
	cb := NewCircuitBreaker("callback-test", CircuitBreakerConfig{
		MaxFailures:  1,
		ResetTimeout: 1 * time.Second,
	})
	cb.SetOnStateChange(func(name string, from, to CircuitState) {
		atomic.StoreInt32(&called, 1)
	})

	cb.RecordFailure()

	time.Sleep(10 * time.Millisecond)

	if atomic.LoadInt32(&called) == 0 {
		t.Fatal("expected state change callback to be invoked")
	}
}
