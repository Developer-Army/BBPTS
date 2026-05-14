package services

import (
	"log/slog"
	"math/rand"
	"net/url"
	"sync"
)

// ProxyManager implements an elite proxy reputation and jailing engine.
type ProxyManager struct {
	scores map[string]int
	mu     sync.Mutex
}

var globalProxyManager = &ProxyManager{
	scores: make(map[string]int),
}

// GetHealthyProxy returns a proxy that hasn't been jailed.
func (pm *ProxyManager) GetHealthyProxy(proxies []string) string {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(proxies) == 0 {
		return ""
	}

	// Initialize scores for new proxies
	for _, p := range proxies {
		if _, exists := pm.scores[p]; !exists {
			pm.scores[p] = 100
		}
	}

	var healthy []string
	for _, p := range proxies {
		if pm.scores[p] > 0 { // 0 means jailed
			healthy = append(healthy, p)
		}
	}

	if len(healthy) == 0 {
		slog.Warn("All proxies jailed! Forcing a proxy resurrection cycle.")
		// Resurrect proxies
		for _, p := range proxies {
			pm.scores[p] = 100
			healthy = append(healthy, p)
		}
	}

	return healthy[rand.Intn(len(healthy))]
}

// JailProxy penalizes a proxy for hitting WAF blocks or rate limits.
func (pm *ProxyManager) JailProxy(proxyURL *url.URL) {
	if proxyURL == nil {
		return
	}
	proxyStr := proxyURL.String()
	
	pm.mu.Lock()
	defer pm.mu.Unlock()
	
	if score, exists := pm.scores[proxyStr]; exists {
		pm.scores[proxyStr] = score - 50 // Two strikes and you're jailed
		if pm.scores[proxyStr] <= 0 {
			slog.Warn("Proxy jailed due to low reputation", "proxy", proxyStr)
		} else {
			slog.Debug("Proxy penalized", "proxy", proxyStr, "new_score", pm.scores[proxyStr])
		}
	}
}

// GetGlobalProxyManager returns the singleton manager.
func GetGlobalProxyManager() *ProxyManager {
	return globalProxyManager
}
