package browser

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/playwright-community/playwright-go"
)

type Instrumenter struct {
	pw              *playwright.Playwright
	browser         playwright.Browser
	idPool          *IdentityPool
	mu              sync.Mutex
	isClosed        bool
	config          InstrumenterConfig
	healthCheck     *time.Ticker
	restartChan     chan struct{}
	pageLoadCount   int
	crashCount      int
	lastRestartTime time.Time
}

type InstrumenterConfig struct {
	MaxMemoryMB     int           // Maximum memory per browser instance in MB (0 = unlimited)
	MaxPageLoads    int           // Maximum page loads before browser restart (for crash recovery)
	RestartInterval time.Duration // Interval between browser restarts for memory cleanup
	HealthCheckFreq time.Duration // Frequency of health checks
}

func NewInstrumenter(idPool *IdentityPool, config InstrumenterConfig) (*Instrumenter, error) {
	err := playwright.Install()
	if err != nil {
		slog.Warn("Playwright install output (may already be installed)", "error", err)
	}

	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("could not start playwright: %w", err)
	}

	args := []string{
		"--disable-blink-features=AutomationControlled",
		"--disable-web-security",
		"--disable-features=IsolateOrigins,site-per-process",
	}

	if config.MaxMemoryMB > 0 {
		args = append(args, fmt.Sprintf("--max-old-space-size=%d", config.MaxMemoryMB))
	}

	browser, err := pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args:     args,
	})
	if err != nil {
		if errStop := pw.Stop(); errStop != nil {
			slog.Warn("Failed to stop playwright", "error", errStop)
		}
		return nil, fmt.Errorf("could not launch browser: %w", err)
	}

	inst := &Instrumenter{
		pw:              pw,
		browser:         browser,
		idPool:          idPool,
		config:          config,
		restartChan:     make(chan struct{}, 1),
		lastRestartTime: time.Now(),
	}

	if config.HealthCheckFreq == 0 {
		config.HealthCheckFreq = 30 * time.Second
	}
	if config.MaxPageLoads == 0 {
		config.MaxPageLoads = 100
	}
	if config.RestartInterval == 0 {
		config.RestartInterval = 1 * time.Hour
	}

	inst.healthCheck = time.NewTicker(config.HealthCheckFreq)
	go inst.healthMonitor()

	slog.Info("Browser instrumenter initialized", "max_memory_mb", config.MaxMemoryMB, "max_page_loads", config.MaxPageLoads)

	return inst, nil
}

type ReconData struct {
	URL          string
	DOMMutations []string
	XHRRequests  []string
	JSFiles      []string
	ConsoleLogs  []string
	StorageKeys  []string
}

func (i *Instrumenter) ExtractSurface(ctx context.Context, targetURL, sessionID string) (*ReconData, error) {
	i.mu.Lock()
	if i.isClosed {
		i.mu.Unlock()
		return nil, fmt.Errorf("instrumenter is closed")
	}
	i.mu.Unlock()

	if i.shouldRestartBrowser() {
		slog.Info("Restarting browser due to resource limits", "page_loads", i.pageLoadCount)
		if err := i.restartBrowser(); err != nil {
			slog.Error("Failed to restart browser", "error", err)
			return nil, fmt.Errorf("browser restart failed: %w", err)
		}
	}

	identity := i.idPool.GetOrCreate(sessionID)
	if identity.Burned {
		return nil, fmt.Errorf("identity %s is burned, skipping", identity.ID)
	}

	contextOptions := playwright.BrowserNewContextOptions{
		UserAgent:         playwright.String(identity.UserAgent),
		Viewport:          &playwright.Size{Width: identity.ViewportWidth, Height: identity.ViewportHeight},
		DeviceScaleFactor: playwright.Float(identity.DeviceScaleFactor),
		Locale:            playwright.String(identity.Locale),
		TimezoneId:        playwright.String(identity.TimezoneID),
		IsMobile:          playwright.Bool(identity.IsMobile),
		HasTouch:          playwright.Bool(identity.HasTouch),
	}

	bCtx, err := i.browser.NewContext(contextOptions)
	if err != nil {
		i.crashCount++
		slog.Warn("Failed to create context, attempting browser restart", "error", err)
		if err := i.restartBrowser(); err != nil {
			return nil, fmt.Errorf("context creation failed and restart failed: %w", err)
		}
		bCtx, err = i.browser.NewContext(contextOptions)
		if err != nil {
			return nil, fmt.Errorf("context creation retry failed: %w", err)
		}
	}
	defer bCtx.Close()

	err = bCtx.AddInitScript(playwright.Script{
		Content: playwright.String(`
			Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
			window.chrome = { runtime: {} };
			Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3] };
		`),
	})
	if err != nil {
		slog.Warn("Failed to inject stealth script", "error", err)
	}

	page, err := bCtx.NewPage()
	if err != nil {
		i.crashCount++
		return nil, fmt.Errorf("failed to create page: %w", err)
	}

	data := &ReconData{
		URL: targetURL,
	}

	page.On("request", func(request playwright.Request) {
		switch reqType := request.ResourceType(); reqType {
		case "xhr", "fetch", "websocket":
			data.XHRRequests = append(data.XHRRequests, request.URL())
		case "script":
			data.JSFiles = append(data.JSFiles, request.URL())
		}
	})

	page.On("console", func(msg playwright.ConsoleMessage) {
		data.ConsoleLogs = append(data.ConsoleLogs, msg.Text())
	})

	navOpts := playwright.PageGotoOptions{
		Timeout:   playwright.Float(30000),
		WaitUntil: playwright.WaitUntilStateNetworkidle,
	}

	resp, err := page.Goto(targetURL, navOpts)
	if err != nil {
		i.crashCount++
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	i.pageLoadCount++

	if resp != nil && (resp.Status() == 403 || resp.Status() == 429) {
		i.idPool.ReportChallenge(sessionID)
		slog.Warn("WAF/Challenge detected", "url", targetURL, "status", resp.Status())
	} else if resp != nil {

		storageKeys, err := page.Evaluate(`Object.keys(localStorage)`)
		if err == nil {
			if keys, ok := storageKeys.([]interface{}); ok {
				for _, k := range keys {
					if str, ok := k.(string); ok {
						data.StorageKeys = append(data.StorageKeys, str)

						if strings.Contains(strings.ToLower(str), "token") || strings.Contains(strings.ToLower(str), "auth") {
							slog.Info("Auth token found in local storage", "url", targetURL, "key", str)
						}
					}
				}
			}
		}
	}

	return data, nil
}

func (i *Instrumenter) shouldRestartBrowser() bool {

	if i.config.MaxPageLoads > 0 && i.pageLoadCount >= i.config.MaxPageLoads {
		return true
	}

	if i.config.MaxMemoryMB > 0 {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		memoryMB := m.Alloc / (1024 * 1024)
		if memoryMB > uint64(i.config.MaxMemoryMB) {
			return true
		}
	}

	if i.config.RestartInterval > 0 && time.Since(i.lastRestartTime) > i.config.RestartInterval {
		return true
	}

	if i.crashCount > 3 {
		return true
	}

	return false
}

func (i *Instrumenter) restartBrowser() error {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.browser.Close(); err != nil {
		slog.Warn("Error closing browser during restart", "error", err)
	}

	args := []string{
		"--disable-blink-features=AutomationControlled",
		"--disable-web-security",
		"--disable-features=IsolateOrigins,site-per-process",
	}

	if i.config.MaxMemoryMB > 0 {
		args = append(args, fmt.Sprintf("--max-old-space-size=%d", i.config.MaxMemoryMB))
	}

	browser, err := i.pw.Chromium.Launch(playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args:     args,
	})
	if err != nil {
		return fmt.Errorf("failed to launch browser: %w", err)
	}

	i.browser = browser
	i.pageLoadCount = 0
	i.crashCount = 0
	i.lastRestartTime = time.Now()

	slog.Info("Browser restarted successfully")
	return nil
}

func (i *Instrumenter) healthMonitor() {
	for {
		select {
		case <-i.healthCheck.C:
			i.mu.Lock()
			if i.isClosed {
				i.mu.Unlock()
				return
			}

			// Update memory stats
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			memoryMB := m.Alloc / (1024 * 1024)

			slog.Debug("Browser health check", "page_loads", i.pageLoadCount, "memory_mb", memoryMB, "crashes", i.crashCount)

			if i.shouldRestartBrowser() {
				slog.Info("Health check triggering browser restart", "page_loads", i.pageLoadCount, "memory_mb", memoryMB)
				go func() {
					i.mu.Unlock()
					if err := i.restartBrowser(); err != nil {
						slog.Error("Health check restart failed", "error", err)
					}
				}()
			} else {
				i.mu.Unlock()
			}

		case <-i.restartChan:

		}
	}
}

func (i *Instrumenter) GetStats() map[string]interface{} {
	i.mu.Lock()
	defer i.mu.Unlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return map[string]interface{}{
		"page_loads":     i.pageLoadCount,
		"crash_count":    i.crashCount,
		"memory_bytes":   m.Alloc,
		"memory_mb":      m.Alloc / (1024 * 1024),
		"uptime_seconds": time.Since(i.lastRestartTime).Seconds(),
		"max_memory_mb":  i.config.MaxMemoryMB,
		"max_page_loads": i.config.MaxPageLoads,
	}
}

func (i *Instrumenter) Close() {
	i.mu.Lock()
	defer i.mu.Unlock()
	if !i.isClosed {
		i.isClosed = true
		if errClose := i.browser.Close(); errClose != nil {
			slog.Warn("Failed to close browser", "error", errClose)
		}
		if errStop := i.pw.Stop(); errStop != nil {
			slog.Warn("Failed to stop playwright", "error", errStop)
		}
	}
}
