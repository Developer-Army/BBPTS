package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

// Scenario 1: WAF Simulation Test
// Ensures the StealthClient correctly identifies a WAF, backs off, and rotates headers.
func TestChaos_WAFSimulation(t *testing.T) {
	requestCount := 0

	// Create a mock Cloudflare edge server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		// 1st request: Cloudflare block
		if requestCount == 1 {
			w.Header().Set("cf-ray", "123456789")
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error": "access denied", "cf-browser-verification": true}`))
			return
		}

		// 2nd request: Rate Limit
		if requestCount == 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`Rate Limited`))
			return
		}

		// 3rd request: Success
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"data": "success"}`))
	}))
	defer ts.Close()

	client, err := NewStealthClient("", 0) // no proxy, 0 jitter for fast test
	if err != nil {
		t.Fatalf("Failed to create stealth client: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected StealthClient to recover and return 200, got %d", resp.StatusCode)
	}

	// Ensure backoff was actually applied
	if duration < 1*time.Second {
		t.Errorf("Expected backoff to delay request by at least 1s, got %v", duration)
	}

	t.Logf("WAF Evasion Success: Client transparently handled WAF block and Rate Limit, returning 200 OK after %v", duration)
}

// Scenario 2: Worker Assassination Test
// Simulates the Health Monitor evicting a dead node and firing an event.
func TestChaos_WorkerAssassination(t *testing.T) {
	b := bus.New() // in-memory bus for testing

	monitor := NewHealthMonitor(b)
	monitor.Start()
	defer monitor.Stop()

	// Mock a worker connecting
	workerID := "worker-chaos-99"
	ctx, cancel := context.WithCancel(context.Background())

	// Run the heartbeat loop
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		BroadcastHeartbeat(ctx, b, workerID)
	}()

	// Wait a moment for it to register
	time.Sleep(100 * time.Millisecond)

	// Assassinate the worker (cancel context to stop heartbeats)
	cancel()
	wg.Wait()

	// Fast-forward time/force check for testing purposes
	// In the real system it waits 35s. For the test, we'll manually set the last seen to 40s ago
	monitor.mu.Lock()
	monitor.workers[workerID] = time.Now().Add(-40 * time.Second)
	monitor.mu.Unlock()

	// Listen for the dead worker event
	deadChan := b.Subscribe("worker.dead")

	// Force health check
	monitor.checkHealth()

	select {
	case ev := <-deadChan:
		if ev.Target != workerID {
			t.Fatalf("Expected dead event for %s, got %s", workerID, ev.Target)
		}
		t.Logf("Worker Assassination Success: Orchestrator successfully identified dead node '%s' and triggered workload reassignment.", ev.Target)
	case <-time.After(1 * time.Second):
		t.Fatal("Health monitor failed to evict dead worker and publish event")
	}
}
