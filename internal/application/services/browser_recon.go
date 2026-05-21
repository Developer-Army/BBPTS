package services

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/browser"
	"github.com/playwright-community/playwright-go"
)

// BrowserRecon utilizes Playwright to perform deep SPA crawling, dynamic DOM analysis,
// and runtime JS endpoint extraction with session pooling and network interception.
type BrowserRecon struct {
	pool *browser.PooledBrowser
}

func (b *BrowserRecon) Name() string {
	return "browser_advanced"
}

// NewBrowserRecon creates a new advanced browser recon with pool.
func NewBrowserRecon() (*BrowserRecon, error) {
	cfg := browser.DefaultPoolConfig()
	cfg.MaxBrowsers = 3
	cfg.MaxContexts = 15
	cfg.ContextTTL = 5 * time.Minute

	pool, err := browser.NewPooledBrowser(cfg)
	if err != nil {
		return nil, err
	}
	return &BrowserRecon{pool: pool}, nil
}

func (b *BrowserRecon) Close() error {
	if b.pool != nil {
		return b.pool.Close()
	}
	return nil
}

func (b *BrowserRecon) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var httpTargets []string
	for _, t := range targets {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			httpTargets = append(httpTargets, t)
		}
	}
	if len(httpTargets) == 0 {
		return nil, nil
	}

	var allEvents []Event
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for _, target := range httpTargets {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			events, err := b.analyzePage(ctx, url)
			if err != nil {
				slog.Debug("Browser analysis failed", "target", url, "error", err)
				return
			}

			mu.Lock()
			allEvents = append(allEvents, events...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return allEvents, nil
}

func (b *BrowserRecon) analyzePage(ctx context.Context, targetURL string) ([]Event, error) {
	// Determine domain for context reuse
	domain := extractDomain(targetURL)

	// Get context from pool
	ctxBrowser, err := b.pool.GetContext(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get browser context: %w", err)
	}
	defer b.pool.ReleaseContext(domain, ctxBrowser)

	page, err := ctxBrowser.NewPage()
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %w", err)
	}
	defer page.Close()

	var events []Event
	var mu sync.Mutex

	// StoreJSResponse: capture response bodies for interesting JS files
	page.OnResponse(func(resp playwright.Response) {
		url := resp.URL()
		if strings.HasSuffix(url, ".js") || strings.Contains(url, ".js?") {
			body, err := resp.Body()
			if err == nil {
				hash := computeSHA256(body)
				mu.Lock()
				events = append(events, NewEvent(url, b.Name(), "js_file", map[string]string{
					"source_page":  targetURL,
					"content_hash": hash,
					"size":         fmt.Sprintf("%d", len(body)),
				}))
				mu.Unlock()
			}
		}
	})

	// Intercept network requests (XHR/fetch/WS)
	page.OnRequest(func(req playwright.Request) {
		u := req.URL()
		method := req.Method()

		// Capture API calls
		if req.ResourceType() == "fetch" || req.ResourceType() == "xhr" ||
			strings.Contains(u, "/api/") || strings.Contains(u, "graphql") {
			mu.Lock()
			events = append(events, NewEvent(u, b.Name(), "api_endpoint", map[string]string{
				"method":      method,
				"source_page": targetURL,
				"request_id":  computeSHA256([]byte(method + " " + u)),
			}))
			mu.Unlock()
		}

		// Detect WebSocket upgrade
		if headerValue(req.Headers(), "upgrade") == "websocket" {
			mu.Lock()
			events = append(events, NewEvent(u, b.Name(), "websocket_endpoint", map[string]string{
				"source_page": targetURL,
			}))
			mu.Unlock()
		}

		// Track external scripts (CDNs)
		if strings.HasSuffix(u, ".js") && (strings.Contains(u, "cdn") || strings.Contains(u, "cloudfront") || strings.Contains(u, "akamai")) {
			mu.Lock()
			events = append(events, NewEvent(u, b.Name(), "external_js", map[string]string{
				"source_page": targetURL,
				"cdn":         detectCDN(u),
			}))
			mu.Unlock()
		}
	})

	// Navigate with timeout and wait for network idle
	_, err = page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(15000),
	})
	if err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	// Extract links (a tags)
	links, err := page.Locator("a[href]").All()
	if err == nil {
		for _, link := range links {
			href, err := link.GetAttribute("href")
			if err == nil && href != "" && (strings.HasPrefix(href, "http") || strings.HasPrefix(href, "/")) {
				mu.Lock()
				events = append(events, NewEvent(href, b.Name(), "link", map[string]string{
					"source_page": targetURL,
				}))
				mu.Unlock()
			}
		}
	}

	// SPA route detection: capture URL changes after navigation
	page.On("framenavigated", func(args ...interface{}) {
		if frame, ok := args[0].(playwright.Frame); ok {
			url := frame.URL()
			mu.Lock()
			events = append(events, NewEvent(url, b.Name(), "spa_route", map[string]string{
				"source_page": targetURL,
			}))
			mu.Unlock()
		}
	})

	// Optional: capture screenshot on error (error detection can be enhanced later)
	// Skipped for performance - enable selectively based on config

	return events, nil
}

// extractDomain extracts registered domain from URL (e.g., "example.com" from "https://app.example.com/path").
func extractDomain(urlStr string) string {
	// Strip scheme
	if strings.HasPrefix(urlStr, "http://") {
		urlStr = strings.TrimPrefix(urlStr, "http://")
	} else if strings.HasPrefix(urlStr, "https://") {
		urlStr = strings.TrimPrefix(urlStr, "https://")
	}
	// Remove path/query
	if idx := strings.Index(urlStr, "/"); idx >= 0 {
		urlStr = urlStr[:idx]
	}
	// Remove port
	if idx := strings.Index(urlStr, ":"); idx >= 0 {
		urlStr = urlStr[:idx]
	}
	// For subdomain stripping to get eTLD+1, you'd need publicsuffix list.
	// For pooling, we can use the full host (subdomain included) - more granular.
	return strings.ToLower(urlStr)
}

func computeSHA256(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}

func headerValue(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return strings.ToLower(v)
		}
	}
	return ""
}

func detectCDN(url string) string {
	lower := strings.ToLower(url)
	switch {
	case strings.Contains(lower, "cloudfront"):
		return "cloudfront"
	case strings.Contains(lower, "cloudflare"):
		return "cloudflare"
	case strings.Contains(lower, "akamai"):
		return "akamai"
	case strings.Contains(lower, "fastly"):
		return "fastly"
	}
	return "unknown"
}
