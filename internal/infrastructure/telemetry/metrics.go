package telemetry

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Queue Metrics
	QueueLag = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_queue_lag",
		Help: "Number of pending recon jobs in the queue",
	}, []string{"queue", "backend"})

	QueueDepth = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_queue_depth",
		Help: "Current depth of the queue (total messages)",
	}, []string{"queue", "backend"})

	QueueMessageRate = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bbpts_queue_messages_total",
		Help: "Total number of messages processed through the queue",
	}, []string{"queue", "backend", "direction"})

	// Worker Metrics
	WorkerCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_worker_count",
		Help: "Number of active workers",
	}, []string{"worker_type", "status"})

	WorkerTaskDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bbpts_worker_task_duration_seconds",
		Help:    "Duration of worker task execution",
		Buckets: []float64{0.1, 0.5, 1, 5, 10, 30, 60, 120, 300},
	}, []string{"worker_type", "task_type"})

	WorkerTaskErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bbpts_worker_task_errors_total",
		Help: "Total number of worker task errors",
	}, []string{"worker_type", "task_type", "error_type"})

	WorkerHeartbeat = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_worker_heartbeat_timestamp",
		Help: "Last heartbeat timestamp from workers",
	}, []string{"worker_id"})

	// Browser/Crawl Metrics
	BrowserPoolSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_browser_pool_size",
		Help: "Current size of browser pool",
	}, []string{"browser_type"})

	BrowserActiveCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_browser_active_count",
		Help: "Number of active browser instances",
	}, []string{"browser_type"})

	BrowserPageLoadDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bbpts_browser_page_load_duration_seconds",
		Help:    "Duration of page loads in browser",
		Buckets: []float64{0.5, 1, 2, 5, 10, 20, 30, 60},
	}, []string{"browser_type"})

	BrowserCrashCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bbpts_browser_crashes_total",
		Help: "Total number of browser crashes",
	}, []string{"browser_type"})

	BrowserMemoryUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_browser_memory_bytes",
		Help: "Memory usage of browser instances",
	}, []string{"browser_type"})

	// Recon Tool Metrics
	ToolExecutionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bbpts_tool_execution_duration_seconds",
		Help:    "Duration of recon tool execution",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600},
	}, []string{"tool", "stage"})

	ToolSuccessRate = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bbpts_tool_executions_total",
		Help: "Total number of tool executions",
	}, []string{"tool", "status"})

	ToolOutputSize = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bbpts_tool_output_size_bytes",
		Help:    "Size of tool output in bytes",
		Buckets: []float64{1024, 10240, 102400, 1048576, 10485760, 104857600},
	}, []string{"tool"})

	// Checkpoint/State Metrics
	CheckpointCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_checkpoint_count",
		Help: "Number of active checkpoints",
	}, []string{"session_id", "stage"})

	CheckpointProgress = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_checkpoint_progress",
		Help: "Progress of checkpoints (0.0 to 1.0)",
	}, []string{"session_id", "stage", "target"})

	SessionDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bbpts_session_duration_seconds",
		Help:    "Duration of recon sessions",
		Buckets: []float64{60, 300, 600, 1800, 3600, 7200, 14400},
	}, []string{"session_type"})

	// WAF/Stealth Metrics
	WAFTriggerRates = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bbpts_waf_blocks_total",
		Help: "Total number of WAF blocks triggered",
	}, []string{"waf_type", "target"})

	CAPTCHAChallengeCount = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "bbpts_captcha_challenges_total",
		Help: "Total number of CAPTCHA challenges encountered",
	}, []string{"target", "captcha_type"})

	IdentityBurnRate = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_identity_burn_rate",
		Help: "Rate at which identities are being burned (blocks per minute)",
	}, []string{"identity_pool"})

	// Database/Storage Metrics
	DBQueryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "bbpts_db_query_duration_seconds",
		Help:    "Duration of database queries",
		Buckets: []float64{0.001, 0.01, 0.1, 0.5, 1, 5},
	}, []string{"operation", "table"})

	DBConnectionPool = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_db_connections",
		Help: "Number of database connections",
	}, []string{"state"})

	StorageUsage = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "bbpts_storage_usage_bytes",
		Help: "Storage usage in bytes",
	}, []string{"storage_type"})

	// System Metrics
	GoroutineCount = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "bbpts_goroutines",
		Help: "Current number of goroutines",
	})

	MemoryUsage = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "bbpts_memory_bytes",
		Help: "Current memory usage in bytes",
	})
)

// MetricsCollector periodically collects system metrics
type MetricsCollector struct {
	interval time.Duration
	stopChan chan struct{}
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(interval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		interval: interval,
		stopChan: make(chan struct{}),
	}
}

// Start begins collecting metrics
func (mc *MetricsCollector) Start() {
	ticker := time.NewTicker(mc.interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				mc.collectSystemMetrics()
			case <-mc.stopChan:
				ticker.Stop()
				return
			}
		}
	}()
}

// Stop stops the metrics collector
func (mc *MetricsCollector) Stop() {
	close(mc.stopChan)
}

// collectSystemMetrics collects system-level metrics
func (mc *MetricsCollector) collectSystemMetrics() {
	// This would typically use runtime.MemStats and other system metrics
	// For now, we'll just log that collection happened
	slog.Debug("System metrics collected")
}

// StartMetricsServer boots an HTTP server exposing Prometheus metrics on the given port (e.g., ":9090")
func StartMetricsServer(addr string) {
	http.Handle("/metrics", promhttp.Handler())
	go func() {
		slog.Info("Starting Prometheus telemetry server", "addr", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			slog.Warn("Prometheus telemetry server stopped", "error", err)
		}
	}()
}
