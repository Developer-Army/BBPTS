package telemetry

import (
	"log/slog"
	"runtime"
	"time"
)

type EnhancedMetricsCollector struct {
	interval time.Duration
	stopChan chan struct{}
}

func NewEnhancedMetricsCollector(interval time.Duration) *EnhancedMetricsCollector {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	return &EnhancedMetricsCollector{
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

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

func (emc *EnhancedMetricsCollector) Stop() {
	close(emc.stopChan)
}

func (emc *EnhancedMetricsCollector) collect() {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	goroutines := runtime.NumGoroutine()
	GoroutineCount.Set(float64(goroutines))

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

type HealthEndpoint struct {
	StartTime time.Time
	Version   string
}

func NewHealthEndpoint(version string) *HealthEndpoint {
	return &HealthEndpoint{
		StartTime: time.Now(),
		Version:   version,
	}
}

func (he *HealthEndpoint) Status() map[string]interface{} {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return map[string]interface{}{
		"status":     "healthy",
		"version":    he.Version,
		"uptime":     time.Since(he.StartTime).String(),
		"goroutines": runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"heap_inuse_mb": memStats.HeapInuse / 1024 / 1024,
			"heap_alloc_mb": memStats.HeapAlloc / 1024 / 1024,
			"sys_mb":        memStats.Sys / 1024 / 1024,
			"num_gc":        memStats.NumGC,
		},
	}
}
