package tools

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/browser"
	"github.com/playwright-community/playwright-go"
)

type BrowserRecon struct {
	pool *browser.PooledBrowser
	mu   sync.Mutex
}

func (b *BrowserRecon) Name() string {
	return "browser_advanced"
}

func NewBrowserRecon() (*BrowserRecon, error) {
	cfg := browser.DefaultPoolConfig()
	cfg.MaxBrowsers = 5
	cfg.MaxContexts = 50
	cfg.ContextTTL = 5 * time.Minute

	pool, err := browser.NewPooledBrowser(cfg)
	if err != nil {
		return nil, err
	}
	return &BrowserRecon{pool: pool}, nil
}

func (b *BrowserRecon) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pool != nil {
		return b.pool.Close()
	}
	return nil
}

func (b *BrowserRecon) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	b.mu.Lock()
	if b.pool == nil {
		cfg := browser.DefaultPoolConfig()
		cfg.MaxBrowsers = 5
		cfg.MaxContexts = 50
		cfg.ContextTTL = 5 * time.Minute

		pool, err := browser.NewPooledBrowser(cfg)
		if err != nil {
			b.mu.Unlock()
			return nil, fmt.Errorf("failed to initialize browser pool: %w", err)
		}
		b.pool = pool
	}
	b.mu.Unlock()

	var httpTargets []string
	for _, t := range targets {
		if strings.HasPrefix(t, "http://") || strings.HasPrefix(t, "https://") {
			httpTargets = append(httpTargets, t)
		}
	}
	if len(httpTargets) == 0 {
		return nil, nil
	}

	var allEvents []recon.Event
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

			events, err := b.analyzePage(ctx, scanCtx, url)
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

func (b *BrowserRecon) analyzePage(_ context.Context, scanCtx *recon.ScanContext, targetURL string) ([]recon.Event, error) {

	domain := extractDomain(targetURL)

	headers := scanCtx.Headers
	ctxBrowser, err := b.pool.GetContext(domain, headers)
	if err != nil {
		return nil, fmt.Errorf("failed to get browser context: %w", err)
	}
	defer b.pool.ReleaseContext(domain, ctxBrowser)

	page, err := ctxBrowser.NewPage()
	if err != nil {
		return nil, fmt.Errorf("failed to create page: %w", err)
	}
	defer page.Close()

	var events []recon.Event
	var mu sync.Mutex

	page.OnResponse(func(resp playwright.Response) {
		url := resp.URL()
		if strings.HasSuffix(url, ".js") || strings.Contains(url, ".js?") {
			body, err := resp.Body()
			if err == nil {
				hash := computeSHA256(body)
				mu.Lock()
				events = append(events, recon.NewEvent(url, b.Name(), "js_file", map[string]string{
					"source_page":  targetURL,
					"content_hash": hash,
					"size":         fmt.Sprintf("%d", len(body)),
				}))
				mu.Unlock()
			}
		}
	})

	page.OnRequest(func(req playwright.Request) {
		u := req.URL()
		method := req.Method()

		if req.ResourceType() == "fetch" || req.ResourceType() == "xhr" ||
			strings.Contains(u, "/api/") || strings.Contains(u, "graphql") {
			mu.Lock()
			events = append(events, recon.NewEvent(u, b.Name(), "api_endpoint", map[string]string{
				"method":      method,
				"source_page": targetURL,
				"request_id":  computeSHA256([]byte(method + " " + u)),
			}))
			mu.Unlock()
		}

		if headerValue(req.Headers(), "upgrade") == "websocket" {
			mu.Lock()
			events = append(events, recon.NewEvent(u, b.Name(), "websocket_endpoint", map[string]string{
				"source_page": targetURL,
			}))
			mu.Unlock()
		}

		if strings.HasSuffix(u, ".js") && (strings.Contains(u, "cdn") || strings.Contains(u, "cloudfront") || strings.Contains(u, "akamai")) {
			mu.Lock()
			events = append(events, recon.NewEvent(u, b.Name(), "external_js", map[string]string{
				"source_page": targetURL,
				"cdn":         detectCDN(u),
			}))
			mu.Unlock()
		}
	})

	_, err = page.Goto(targetURL, playwright.PageGotoOptions{
		WaitUntil: playwright.WaitUntilStateNetworkidle,
		Timeout:   playwright.Float(15000),
	})
	if err != nil {
		return nil, fmt.Errorf("navigation failed: %w", err)
	}

	links, err := page.Locator("a[href]").All()
	if err == nil {
		for _, link := range links {
			href, err := link.GetAttribute("href")
			if err == nil && href != "" && (strings.HasPrefix(href, "http") || strings.HasPrefix(href, "/")) {
				mu.Lock()
				events = append(events, recon.NewEvent(href, b.Name(), "link", map[string]string{
					"source_page": targetURL,
				}))
				mu.Unlock()
			}
		}
	}

	page.On("framenavigated", func(args ...interface{}) {
		if frame, ok := args[0].(playwright.Frame); ok {
			url := frame.URL()
			mu.Lock()
			events = append(events, recon.NewEvent(url, b.Name(), "spa_route", map[string]string{
				"source_page": targetURL,
			}))
			mu.Unlock()
		}
	})

	return events, nil
}

func extractDomain(urlStr string) string {

	if strings.HasPrefix(urlStr, "http://") {
		urlStr = strings.TrimPrefix(urlStr, "http://")
	} else if strings.HasPrefix(urlStr, "https://") {
		urlStr = strings.TrimPrefix(urlStr, "https://")
	}

	if idx := strings.Index(urlStr, "/"); idx >= 0 {
		urlStr = urlStr[:idx]
	}

	if idx := strings.Index(urlStr, ":"); idx >= 0 {
		urlStr = urlStr[:idx]
	}

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
