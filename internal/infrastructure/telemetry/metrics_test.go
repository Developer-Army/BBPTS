package telemetry

import (
	"testing"
	"time"
)

func TestMetricsCollectorStructure(t *testing.T) {
	mc := &MetricsCollector{}
	_ = mc
}

func TestNewMetricsCollector(t *testing.T) {
	interval := 30 * time.Second
	mc := NewMetricsCollector(interval)

	if mc == nil {
		t.Fatal("NewMetricsCollector returned nil")
	}

	if mc.interval != interval {
		t.Errorf("Expected interval %v, got %v", interval, mc.interval)
	}

	if mc.stopChan == nil {
		t.Error("Expected stopChan to be initialized")
	}
}

func TestNewMetricsCollectorDefaultInterval(t *testing.T) {
	mc := NewMetricsCollector(0)

	if mc == nil {
		t.Fatal("NewMetricsCollector returned nil")
	}

	if mc.interval != 0 {
		t.Errorf("Expected interval 0, got %v", mc.interval)
	}
}

func TestMetricsCollectorStart(t *testing.T) {
	mc := NewMetricsCollector(10 * time.Millisecond)

	// Should not panic
	mc.Start()

	// Stop it
	mc.Stop()
}

func TestMetricsCollectorStop(t *testing.T) {
	mc := NewMetricsCollector(10 * time.Millisecond)

	// Should not panic
	mc.Stop()
}

func TestMetricsCollectorStartStop(t *testing.T) {
	mc := NewMetricsCollector(10 * time.Millisecond)

	mc.Start()
	time.Sleep(20 * time.Millisecond)
	mc.Stop()

	// Should complete without hanging
}

func TestMetricsCollectorStopChan(t *testing.T) {
	mc := NewMetricsCollector(10 * time.Millisecond)

	select {
	case <-mc.stopChan:
		t.Error("stopChan should not be closed initially")
	default:
		// Expected
	}

	mc.Stop()

	select {
	case <-mc.stopChan:
		// Expected - channel should be closed
	case <-time.After(100 * time.Millisecond):
		t.Error("stopChan should be closed after Stop()")
	}
}

func TestStartMetricsServer(t *testing.T) {
	// This starts a goroutine, so we can't easily test it
	// Just verify it doesn't panic
	StartMetricsServer(":9090")

	// Give it a moment to start
	time.Sleep(10 * time.Millisecond)
}

func TestStartMetricsServerDifferentPort(t *testing.T) {
	// Test with different port
	StartMetricsServer(":9091")

	time.Sleep(10 * time.Millisecond)
}

func TestStartMetricsServerDefaultAddr(t *testing.T) {
	// Test with default address format
	StartMetricsServer(":0")

	time.Sleep(10 * time.Millisecond)
}

func TestMetricsCollectorInterval(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
	}{
		{"1 second", 1 * time.Second},
		{"30 seconds", 30 * time.Second},
		{"1 minute", 1 * time.Minute},
		{"5 minutes", 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mc := NewMetricsCollector(tt.interval)
			if mc.interval != tt.interval {
				t.Errorf("Expected interval %v, got %v", tt.interval, mc.interval)
			}
		})
	}
}

func TestMetricsCollectorNilStopChan(t *testing.T) {
	mc := &MetricsCollector{
		interval: 10 * time.Millisecond,
		stopChan: nil,
	}

	// Should handle nil stopChan gracefully (though it shouldn't happen in practice)
	// This is more of a defensive test
	if mc.interval != 10*time.Millisecond {
		t.Errorf("Expected interval 10ms, got %v", mc.interval)
	}
	if mc.stopChan != nil {
		t.Error("Expected stopChan to be nil")
	}
}

func TestCollectSystemMetrics(t *testing.T) {
	mc := NewMetricsCollector(10 * time.Millisecond)

	// This method is called internally by the ticker
	// We can call it directly to test it doesn't panic
	mc.collectSystemMetrics()
}

func TestMetricsCollectorConcurrentStartStop(t *testing.T) {
	mc := NewMetricsCollector(10 * time.Millisecond)

	// Start multiple times
	mc.Start()
	mc.Start()

	// Stop multiple times
	mc.Stop()
	mc.Stop()

	// Should not panic
}

func TestMetricsCollectorLongInterval(t *testing.T) {
	mc := NewMetricsCollector(1 * time.Hour)

	if mc.interval != 1*time.Hour {
		t.Errorf("Expected interval 1 hour, got %v", mc.interval)
	}

	mc.Start()
	mc.Stop()
}

func TestMetricsCollectorShortInterval(t *testing.T) {
	mc := NewMetricsCollector(1 * time.Millisecond)

	if mc.interval != 1*time.Millisecond {
		t.Errorf("Expected interval 1ms, got %v", mc.interval)
	}

	mc.Start()
	time.Sleep(5 * time.Millisecond)
	mc.Stop()
}

func TestMetricsCollectorZeroInterval(t *testing.T) {
	mc := NewMetricsCollector(0)

	if mc.interval != 0 {
		t.Errorf("Expected interval 0, got %v", mc.interval)
	}

	mc.Start()
	mc.Stop()
}

func TestMetricsCollectorNegativeInterval(t *testing.T) {
	mc := NewMetricsCollector(-1 * time.Second)

	if mc.interval != -1*time.Second {
		t.Errorf("Expected interval -1s, got %v", mc.interval)
	}

	// Should handle negative interval gracefully
	mc.Start()
	mc.Stop()
}
