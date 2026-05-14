package network

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ResidentialProxy represents a residential proxy endpoint with health tracking.
type ResidentialProxy struct {
	URL             string    // Proxy URL (http://ip:port or socks5://ip:port)
	Provider        string    // Provider name (luminati, smartproxy, oxylabs, etc.)
	LastHealthCheck time.Time // Last health check timestamp
	FailureCount    int       // Consecutive failures
	MaxFailures     int       // Max failures before rotation
	IsHealthy       bool      // Current health status
}

// ProxyPool manages residential proxy rotation with automatic fallback.
type ProxyPool struct {
	proxies       []*ResidentialProxy
	currentIdx    int
	mu            sync.RWMutex
	healthTicker  *time.Ticker
	client        *http.Client
	checkInterval time.Duration
}

// NewProxyPool creates a pool of residential proxies with health monitoring.
func NewProxyPool(proxyURLs []string, providers []string, healthCheckInterval time.Duration) (*ProxyPool, error) {
	if len(proxyURLs) == 0 {
		return nil, fmt.Errorf("at least one proxy URL is required")
	}

	pp := &ProxyPool{
		proxies:       make([]*ResidentialProxy, 0),
		currentIdx:    0,
		checkInterval: healthCheckInterval,
	}

	// Initialize proxies
	for i, proxyURL := range proxyURLs {
		provider := "unknown"
		if i < len(providers) {
			provider = providers[i]
		}

		pp.proxies = append(pp.proxies, &ResidentialProxy{
			URL:         proxyURL,
			Provider:    provider,
			MaxFailures: 5,
			IsHealthy:   true,
		})
	}

	// Start health check goroutine
	pp.healthTicker = time.NewTicker(healthCheckInterval)
	go pp.healthCheckLoop()

	slog.Info("Residential proxy pool initialized", "count", len(pp.proxies), "interval_ms", healthCheckInterval.Milliseconds())
	return pp, nil
}

// GetProxyClient returns an HTTP client using the next available proxy.
func (pp *ProxyPool) GetProxyClient(ctx context.Context) (*http.Client, *ResidentialProxy, error) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	if len(pp.proxies) == 0 {
		return nil, nil, fmt.Errorf("no proxies available")
	}

	// Find next healthy proxy
	startIdx := pp.currentIdx
	for i := 0; i < len(pp.proxies); i++ {
		idx := (startIdx + i) % len(pp.proxies)
		proxy := pp.proxies[idx]

		if proxy.IsHealthy {
			pp.currentIdx = (idx + 1) % len(pp.proxies)

			client, err := pp.createProxyClient(proxy.URL)
			if err != nil {
				pp.markFailure(proxy)
				continue
			}

			return client, proxy, nil
		}
	}

	// Fallback to first proxy if none are healthy
	proxy := pp.proxies[0]
	client, err := pp.createProxyClient(proxy.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("all proxies unavailable: %w", err)
	}

	return client, proxy, nil
}

// createProxyClient creates an HTTP client configured to use the given proxy.
func (pp *ProxyPool) createProxyClient(proxyURL string) (*http.Client, error) {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(u),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// MarkSuccess marks a proxy as working correctly.
func (pp *ProxyPool) MarkSuccess(proxy *ResidentialProxy) {
	if proxy == nil {
		return
	}

	pp.mu.Lock()
	defer pp.mu.Unlock()

	proxy.FailureCount = 0
	proxy.LastHealthCheck = time.Now()
	proxy.IsHealthy = true
}

// markFailure marks a proxy as having failed.
func (pp *ProxyPool) markFailure(proxy *ResidentialProxy) {
	proxy.FailureCount++
	proxy.LastHealthCheck = time.Now()

	if proxy.FailureCount >= proxy.MaxFailures {
		proxy.IsHealthy = false
		slog.Warn("Proxy marked unhealthy", "proxy", proxy.URL, "failures", proxy.FailureCount)
	}
}

// healthCheckLoop periodically tests proxy health.
func (pp *ProxyPool) healthCheckLoop() {
	for range pp.healthTicker.C {
		pp.mu.Lock()
		for _, proxy := range pp.proxies {
			// Simple health check: try to connect to a stable endpoint
			go pp.checkProxyHealth(proxy)
		}
		pp.mu.Unlock()
	}
}

// checkProxyHealth tests if a proxy is still working.
func (pp *ProxyPool) checkProxyHealth(proxy *ResidentialProxy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := pp.createProxyClient(proxy.URL)
	if err != nil {
		pp.markFailure(proxy)
		return
	}

	// Test against a simple endpoint
	req, err := http.NewRequestWithContext(ctx, "HEAD", "http://www.google.com", nil)
	if err != nil {
		pp.markFailure(proxy)
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		pp.markFailure(proxy)
		return
	}
	defer resp.Body.Close()

	// Any successful response means proxy is healthy
	proxy.FailureCount = 0
	proxy.IsHealthy = true
	proxy.LastHealthCheck = time.Now()
	slog.Debug("Proxy health check passed", "proxy", proxy.URL)
}

// GetRandomProxy returns a random healthy proxy (for diffing/async tasks).
func (pp *ProxyPool) GetRandomProxy() (*ResidentialProxy, error) {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	var healthyProxies []*ResidentialProxy
	for _, proxy := range pp.proxies {
		if proxy.IsHealthy {
			healthyProxies = append(healthyProxies, proxy)
		}
	}

	if len(healthyProxies) == 0 {
		if len(pp.proxies) > 0 {
			return pp.proxies[rand.Intn(len(pp.proxies))], nil
		}
		return nil, fmt.Errorf("no proxies available")
	}

	return healthyProxies[rand.Intn(len(healthyProxies))], nil
}

// GetProxyStats returns current proxy pool statistics.
func (pp *ProxyPool) GetProxyStats() map[string]interface{} {
	pp.mu.RLock()
	defer pp.mu.RUnlock()

	healthyCount := 0
	unhealthyCount := 0
	for _, proxy := range pp.proxies {
		if proxy.IsHealthy {
			healthyCount++
		} else {
			unhealthyCount++
		}
	}

	return map[string]interface{}{
		"total":       len(pp.proxies),
		"healthy":     healthyCount,
		"unhealthy":   unhealthyCount,
		"current_idx": pp.currentIdx,
	}
}

// Close stops the proxy pool health checks.
func (pp *ProxyPool) Close() {
	if pp.healthTicker != nil {
		pp.healthTicker.Stop()
	}
}
