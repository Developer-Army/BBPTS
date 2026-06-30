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

type ResidentialProxy struct {
	URL             string    // Proxy URL (http://ip:port or socks5://ip:port)
	Provider        string    // Provider name (luminati, smartproxy, oxylabs, etc.)
	LastHealthCheck time.Time // Last health check timestamp
	FailureCount    int       // Consecutive failures
	MaxFailures     int       // Max failures before rotation
	IsHealthy       bool      // Current health status
}

type ProxyPool struct {
	proxies       []*ResidentialProxy
	currentIdx    int
	mu            sync.RWMutex
	healthTicker  *time.Ticker
	checkInterval time.Duration
}

func NewProxyPool(proxyURLs []string, providers []string, healthCheckInterval time.Duration) (*ProxyPool, error) {
	if len(proxyURLs) == 0 {
		return nil, fmt.Errorf("at least one proxy URL is required")
	}

	pp := &ProxyPool{
		proxies:       make([]*ResidentialProxy, 0),
		currentIdx:    0,
		checkInterval: healthCheckInterval,
	}

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

	pp.healthTicker = time.NewTicker(healthCheckInterval)
	go pp.healthCheckLoop()

	slog.Info("Residential proxy pool initialized", "count", len(pp.proxies), "interval_ms", healthCheckInterval.Milliseconds())
	return pp, nil
}

func (pp *ProxyPool) GetProxyClient(ctx context.Context) (*http.Client, *ResidentialProxy, error) {
	pp.mu.Lock()
	defer pp.mu.Unlock()

	if len(pp.proxies) == 0 {
		return nil, nil, fmt.Errorf("no proxies available")
	}

	startIdx := pp.currentIdx
	for i := 0; i < len(pp.proxies); i++ {
		idx := (startIdx + i) % len(pp.proxies)
		proxy := pp.proxies[idx]

		if proxy.IsHealthy {
			pp.currentIdx = (idx + 1) % len(pp.proxies)

			client, err := pp.createProxyClient(proxy.URL)
			if err != nil {

				proxy.FailureCount++
				proxy.LastHealthCheck = time.Now()
				if proxy.FailureCount >= proxy.MaxFailures {
					proxy.IsHealthy = false
					slog.Warn("Proxy marked unhealthy", "proxy", proxy.URL, "failures", proxy.FailureCount)
				}
				continue
			}

			return client, proxy, nil
		}
	}

	proxy := pp.proxies[0]
	client, err := pp.createProxyClient(proxy.URL)
	if err != nil {
		return nil, nil, fmt.Errorf("all proxies unavailable: %w", err)
	}

	return client, proxy, nil
}

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

func (pp *ProxyPool) markFailure(proxy *ResidentialProxy) {
	proxy.FailureCount++
	proxy.LastHealthCheck = time.Now()

	if proxy.FailureCount >= proxy.MaxFailures {
		proxy.IsHealthy = false
		slog.Warn("Proxy marked unhealthy", "proxy", proxy.URL, "failures", proxy.FailureCount)
	}
}

func (pp *ProxyPool) healthCheckLoop() {
	for range pp.healthTicker.C {
		pp.mu.Lock()
		for _, proxy := range pp.proxies {

			go pp.checkProxyHealth(proxy)
		}
		pp.mu.Unlock()
	}
}

func (pp *ProxyPool) checkProxyHealth(proxy *ResidentialProxy) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client, err := pp.createProxyClient(proxy.URL)
	if err != nil {
		pp.mu.Lock()
		pp.markFailure(proxy)
		pp.mu.Unlock()
		return
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", "http://www.google.com", nil)
	if err != nil {
		pp.mu.Lock()
		pp.markFailure(proxy)
		pp.mu.Unlock()
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		pp.mu.Lock()
		pp.markFailure(proxy)
		pp.mu.Unlock()
		return
	}
	defer resp.Body.Close()

	pp.mu.Lock()
	proxy.FailureCount = 0
	proxy.IsHealthy = true
	proxy.LastHealthCheck = time.Now()
	pp.mu.Unlock()
	slog.Debug("Proxy health check passed", "proxy", proxy.URL)
}

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

func (pp *ProxyPool) Close() {
	if pp.healthTicker != nil {
		pp.healthTicker.Stop()
	}
}
