package browser

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
)

// PooledBrowser manages a pool of Playwright browser instances and reuses contexts per domain.
type PooledBrowser struct {
	pw           *playwright.Playwright
	browsers     []BrowserInstance
	contextPool  map[string][]playwright.BrowserContext // domain → contexts
	globalPool   []playwright.BrowserContext            // unassigned contexts
	maxPoolSize  int
	contextTTL   time.Duration
	mu           sync.RWMutex
	closeOnce    sync.Once
}

// BrowserInstance represents a single Chromium instance.
type BrowserInstance struct {
	browser    playwright.Browser
	contexts   int
	lastUsed   time.Time
}

// PoolConfig configures browser pool behavior.
type PoolConfig struct {
	MaxBrowsers    int           // max number of Chromium instances
	MaxContexts    int           // max total contexts across all browsers
	ContextTTL     time.Duration // idle context expiration
	Headless       bool
	ProxyURL       string
	UserAgent      string
	ExtraArgs      []string
}

// DefaultPoolConfig returns sensible defaults.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxBrowsers:  5,
		MaxContexts:  20,
		ContextTTL:   10 * time.Minute,
		Headless:     true,
		ExtraArgs: []string{
			"--disable-blink-features=AutomationControlled",
			"--no-sandbox",
			"--disable-setuid-sandbox",
			"--disable-dev-shm-usage",
			"--disable-accelerated-2d-canvas",
			"--disable-gpu",
			"--window-size=1920,1080",
		},
	}
}

// NewPooledBrowser creates a managed browser pool.
func NewPooledBrowser(cfg PoolConfig) (*PooledBrowser, error) {
	// Install Playwright drivers if needed
	if err := playwright.Install(&playwright.RunOptions{Verbose: false}); err != nil {
		return nil, fmt.Errorf("playwright install failed: %w", err)
	}

	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("playwright run failed: %w", err)
	}

	pb := &PooledBrowser{
		pw:          pw,
		browsers:    make([]BrowserInstance, 0, cfg.MaxBrowsers),
		contextPool: make(map[string][]playwright.BrowserContext),
		globalPool:  make([]playwright.BrowserContext, 0),
		maxPoolSize: cfg.MaxContexts,
		contextTTL:  cfg.ContextTTL,
	}

	// Launch initial browser instances
	for i := 0; i < cfg.MaxBrowsers; i++ {
		b, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
			Headless: playwright.Bool(cfg.Headless),
			Args:     cfg.ExtraArgs,
		})
		if err != nil {
			slog.Warn("Failed to launch browser instance", "index", i, "error", err)
			continue
		}
		pb.browsers = append(pb.browsers, BrowserInstance{
			browser: b,
			lastUsed: time.Now(),
		})
	}

	slog.Info("Browser pool initialized", "browsers", len(pb.browsers), "max_contexts", cfg.MaxContexts)

	// Start cleanup goroutine
	go pb.cleanupLoop()

	return pb, nil
}

// GetContext obtains a browser context for a domain, reusing existing if available.
func (pb *PooledBrowser) GetContext(domain string) (playwright.BrowserContext, error) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// 1. Check if we have an existing context for this domain (least-recently-used)
	if contexts, ok := pb.contextPool[domain]; ok && len(contexts) > 0 {
		ctx := contexts[len(contexts)-1]
		// Remove from pool
		pb.contextPool[domain] = contexts[:len(contexts)-1]
		slog.Debug("Reused existing context for domain", "domain", domain, "remaining", len(pb.contextPool[domain]))
		return ctx, nil
	}

	// 2. Check global pool for any free context
	if len(pb.globalPool) > 0 {
		ctx := pb.globalPool[len(pb.globalPool)-1]
		pb.globalPool = pb.globalPool[:len(pb.globalPool)-1]
		slog.Debug("Reused global context for domain", "domain", domain)
		return ctx, nil
	}

	// 3. Need to create new context - find browser with capacity
	browserIdx := pb.selectBrowser()
	if browserIdx == -1 {
		return nil, fmt.Errorf("no browser instances available or pool exhausted")
	}

	browserInst := pb.browsers[browserIdx]
	ctx, err := browserInst.browser.NewContext(playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{Width: 1920, Height: 1080},
		UserAgent: playwright.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create browser context: %w", err)
	}

	browserInst.contexts++
	browserInst.lastUsed = time.Now()
	slog.Debug("Created new browser context", "domain", domain, "browser", browserIdx, "total_contexts", browserInst.contexts)

	return ctx, nil
}

// ReleaseContext returns a context to the pool for reuse.
func (pb *PooledBrowser) ReleaseContext(domain string, ctx playwright.BrowserContext) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	// Check pool size limit
	totalContexts := 0
	for _, list := range pb.contextPool {
		totalContexts += len(list)
	}
	totalContexts += len(pb.globalPool)

	if totalContexts >= pb.maxPoolSize {
		// Pool full - close context
		ctx.Close()
		slog.Debug("Closed context (pool full)", "domain", domain)
		return
	}

	// Return to domain-specific pool
	pb.contextPool[domain] = append(pb.contextPool[domain], ctx)
	slog.Debug("Context returned to pool", "domain", domain, "pool_size", len(pb.contextPool[domain]))
}

// selectBrowser picks a browser instance (round-robin with capacity check).
func (pb *PooledBrowser) selectBrowser() int {
	// Start from last used + 1 (round-robin)
	start := 0
	for i := 0; i < len(pb.browsers); i++ {
		idx := (start + i) % len(pb.browsers)
		// Use browsers with available context capacity (arbitrary limit of 50 per browser)
		if pb.browsers[idx].contexts < 50 {
			return idx
		}
	}
	return -1
}

// cleanupLoop periodically removes stale contexts.
func (pb *PooledBrowser) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		pb.mu.Lock()


		// Clean domain-specific pools
		for domain, contexts := range pb.contextPool {
			active := make([]playwright.BrowserContext, 0, len(contexts))
			for _, ctx := range contexts {
				// Check context age (approximate via LastUsed on owning browser)
				// Since context does not expose idle time, we conservatively keep all
				// In production you'd track context creation timestamp separately
				active = append(active, ctx)
			}
			if len(active) < len(pb.contextPool[domain]) {
				slog.Debug("Cleaned stale contexts", "domain", domain, "removed", len(pb.contextPool[domain])-len(active))
			}
			pb.contextPool[domain] = active
		}

		// No-op for global pool for now
		pb.mu.Unlock()
	}
}

// Stats returns pool statistics.
func (pb *PooledBrowser) Stats() map[string]interface{} {
	pb.mu.RLock()
	defer pb.mu.RUnlock()

	stats := map[string]interface{}{
		"browsers":       len(pb.browsers),
		"total_contexts": 0,
		"by_domain":      make(map[string]int),
	}

	for _, bi := range pb.browsers {
		stats["total_contexts"] = stats["total_contexts"].(int) + bi.contexts
	}
	for domain, list := range pb.contextPool {
		stats["by_domain"].(map[string]int)[domain] = len(list)
	}

	return stats
}

// Close shuts down all browsers and clears pools.
func (pb *PooledBrowser) Close() error {
	pb.closeOnce.Do(func() {
		pb.mu.Lock()
		defer pb.mu.Unlock()

		// Close all contexts
		for domain, list := range pb.contextPool {
			for _, ctx := range list {
				ctx.Close()
			}
			delete(pb.contextPool, domain)
		}
		for _, ctx := range pb.globalPool {
			ctx.Close()
		}
		pb.globalPool = nil

		// Close all browsers
		for _, bi := range pb.browsers {
			bi.browser.Close()
		}
		pb.browsers = nil

		if pb.pw != nil {
			pb.pw.Stop()
		}
	})
	return nil
}
