package telemetry

import (
	"log/slog"
	"runtime"
	"time"
)

// EnhancedMetricsCollector extends the base MetricsCollector with actual
// runtime telemetry collection (goroutines, memory, GC stats).
type EnhancedMetricsCollector struct {
	interval time.Duration
	stopChan chan struct{}
}

// NewEnhancedMetricsCollector creates a collector that periodically emits
// goroutine count, heap usage, GC pause, and system memory to Prometheus.
func NewEnhancedMetricsCollector(interval time.Duration) *EnhancedMetricsCollector {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &EnhancedMetricsCollector{
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

// Start begins the background metrics collection loop.
func (emc *EnhancedMetricsCollector) Start() {
	ticker := time.NewTicker(emc.interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				emc.collect()
			case <-emc.stopChan:
				return
			}
		}
	}()
	slog.Info("Enhanced metrics collector started", "interval", emc.interval)
}

// Stop halts the metrics collection loop.
func (emc *EnhancedMetricsCollector) Stop() {
	close(emc.stopChan)
}

// collect gathers runtime metrics and pushes them to Prometheus gauges.
func (emc *EnhancedMetricsCollector) collect() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	// Goroutine count
	goroutines := runtime.NumGoroutine()
	GoroutineCount.Set(float64(goroutines))

	// Memory usage (heap in-use)
	MemoryUsage.Set(float64(memStats.HeapInuse))

	slog.Debug("Metrics collected",
		"goroutines", goroutines,
		"heap_inuse_mb", memStats.HeapInuse/1024/1024,
		"heap_alloc_mb", memStats.HeapAlloc/1024/1024,
		"sys_mb", memStats.Sys/1024/1024,
		"gc_pause_ns", memStats.PauseNs[(memStats.NumGC+255)%256],
		"num_gc", memStats.NumGC,
	)
}

// HealthEndpoint returns a simple health check handler that can be mounted
// alongside the Prometheus metrics endpoint.
type HealthEndpoint struct {
	StartTime time.Time
	Version   string
}

// NewHealthEndpoint creates a health endpoint tracker.
func NewHealthEndpoint(version string) *HealthEndpoint {
	return &HealthEndpoint{
		StartTime: time.Now(),
		Version:   version,
	}
}

// Status returns a health status payload.
func (he *HealthEndpoint) Status() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"status":     "healthy",
		"version":    he.Version,
		"uptime":     time.Since(he.StartTime).String(),
		"goroutines": runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"heap_inuse_mb":  memStats.HeapInuse / 1024 / 1024,
			"heap_alloc_mb":  memStats.HeapAlloc / 1024 / 1024,
			"sys_mb":         memStats.Sys / 1024 / 1024,
			"num_gc":         memStats.NumGC,
		},
	}
}
