package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/queue"
)

func init() {
	os.Setenv("BBPTS_ALLOW_PRIVATE_IPS", "true")
}

func TestChaos_WAFSimulation(t *testing.T) {
	requestCount := 0

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++

		if requestCount == 1 {
			w.Header().Set("cf-ray", "123456789")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error": "access denied", "cf-browser-verification": true}`))
			return
		}

		if requestCount == 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`Rate Limited`))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data": "success"}`))
	}))
	defer ts.Close()

	client, err := NewStealthClient("", 0)
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

	if duration < 1*time.Second {
		t.Errorf("Expected backoff to delay request by at least 1s, got %v", duration)
	}

	t.Logf("WAF Evasion Success: Client transparently handled WAF block and Rate Limit, returning 200 OK after %v", duration)
}

func TestChaos_WorkerAssassination(t *testing.T) {
	b := queue.New()

	monitor := NewHealthMonitor(b)
	monitor.Start()
	defer monitor.Stop()

	workerID := "worker-chaos-99"
	ctx, cancel := context.WithCancel(context.Background())

	// Run the heartbeat loop
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		BroadcastHeartbeat(ctx, b, workerID)
	}()

	time.Sleep(100 * time.Millisecond)

	cancel()
	wg.Wait()

	monitor.mu.Lock()
	monitor.workers[workerID] = time.Now().Add(-40 * time.Second)
	monitor.mu.Unlock()

	deadChan := b.Subscribe("worker.dead")

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
