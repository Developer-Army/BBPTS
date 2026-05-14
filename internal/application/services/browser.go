package services

import (
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/playwright-community/playwright-go"
)

// StealthBrowser manages a headless Playwright instance configured to evade basic bot detection.
type StealthBrowser struct {
	pw      *playwright.Playwright
	browser playwright.Browser
}

// NewStealthBrowser initializes Playwright and launches a stealthy headless browser.
func NewStealthBrowser(proxy string) (*StealthBrowser, error) {
	// playwright.Install() downloads the browser binaries if not present.
	// This is safe to call multiple times.
	err := playwright.Install(&playwright.RunOptions{
		Verbose: false,
	})
	if err != nil {
		return nil, fmt.Errorf("could not install playwright drivers: %w", err)
	}

	pw, err := playwright.Run()
	if err != nil {
		return nil, fmt.Errorf("could not start playwright: %w", err)
	}

	options := playwright.BrowserTypeLaunchOptions{
		Headless: playwright.Bool(true),
		Args: []string{
			"--disable-blink-features=AutomationControlled", // Prevents navigator.webdriver = true
			"--no-sandbox",
			"--disable-setuid-sandbox",
			"--disable-dev-shm-usage",
			"--disable-accelerated-2d-canvas",
			"--disable-gpu",
			"--window-size=1920,1080",
		},
	}

	if proxy != "" {
		options.Proxy = &playwright.Proxy{
			Server: proxy,
		}
	}

	browser, err := pw.Chromium.Launch(options)
	if err != nil {
		pw.Stop()
		return nil, fmt.Errorf("could not launch chromium: %w", err)
	}

	return &StealthBrowser{
		pw:      pw,
		browser: browser,
	}, nil
}

// Close terminates the browser and playwright instance.
func (sb *StealthBrowser) Close() error {
	if sb.browser != nil {
		sb.browser.Close()
	}
	if sb.pw != nil {
		return sb.pw.Stop()
	}
	return nil
}

// NewPage creates a new browser context and page with randomized viewport and user agent.
func (sb *StealthBrowser) NewPage() (playwright.Page, playwright.BrowserContext, error) {
	// Randomize viewport slightly to avoid fingerprinting
	width := 1800 + rand.Intn(200)
	height := 900 + rand.Intn(200)

	context, err := sb.browser.NewContext(playwright.BrowserNewContextOptions{
		Viewport: &playwright.Size{
			Width:  width,
			Height: height,
		},
		UserAgent:   playwright.String("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
		Locale:      playwright.String("en-US"),
		TimezoneId:  playwright.String("America/New_York"),
		Permissions: []string{"geolocation"},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("could not create context: %w", err)
	}

	// Add stealth scripts to the context before any page loads
	stealthScript := `
		// Overwrite navigator.webdriver
		Object.defineProperty(navigator, 'webdriver', {
			get: () => false,
		});
		// Fake window.chrome
		window.chrome = {
			runtime: {}
		};
		// Fake permissions
		const originalQuery = window.navigator.permissions.query;
		window.navigator.permissions.query = (parameters) => (
			parameters.name === 'notifications' ?
				Promise.resolve({ state: Notification.permission }) :
				originalQuery(parameters)
		);
		// Hide automation indicators
		Object.defineProperty(navigator, 'plugins', {
			get: () => [1, 2, 3, 4, 5],
		});
		Object.defineProperty(navigator, 'languages', {
			get: () => ['en-US', 'en'],
		});
		// Spoof screen properties
		Object.defineProperty(screen, 'availHeight', {
			get: () => window.innerHeight,
		});
		Object.defineProperty(screen, 'availWidth', {
			get: () => window.innerWidth,
		});
		// Disable WebRTC
		Object.defineProperty(navigator, 'mediaDevices', {
			get: () => undefined,
		});
	`
	err = context.AddInitScript(playwright.Script{Content: playwright.String(stealthScript)})
	if err != nil {
		slog.Warn("Failed to inject stealth init script", "error", err)
	}

	page, err := context.NewPage()
	if err != nil {
		context.Close()
		return nil, nil, fmt.Errorf("could not create page: %w", err)
	}

	return page, context, nil
}

// EmulateHuman mimics human behavior on the page to pass behavioral WAF checks.
func (sb *StealthBrowser) EmulateHuman(page playwright.Page) error {
	// Simulate curved mouse movements (pseudo-Bezier)
	startX, startY := float64(rand.Intn(200)), float64(rand.Intn(200))
	_ = page.Mouse().Move(startX, startY)
	
	for i := 0; i < 3; i++ {
		endX := float64(100 + rand.Intn(800))
		endY := float64(100 + rand.Intn(600))
		
		// Control point to simulate a curve
		ctrlX := (startX + endX) / 2.0 + float64(rand.Intn(150) - 75)
		ctrlY := (startY + endY) / 2.0 + float64(rand.Intn(150) - 75)
		
		steps := 25 + rand.Intn(20)
		for j := 1; j <= steps; j++ {
			t := float64(j) / float64(steps)
			// Quadratic Bezier formula
			x := (1-t)*(1-t)*startX + 2*(1-t)*t*ctrlX + t*t*endX
			y := (1-t)*(1-t)*startY + 2*(1-t)*t*ctrlY + t*t*endY
			
			_ = page.Mouse().Move(x, y)
			// Micro-hesitations
			time.Sleep(time.Duration(2 + rand.Intn(8)) * time.Millisecond)
		}
		startX, startY = endX, endY
		time.Sleep(time.Duration(100 + rand.Intn(300)) * time.Millisecond)
	}

	// Randomized scroll with momentum
	scrollAmount := float64(200 + rand.Intn(600))
	scrollSteps := 15 + rand.Intn(10)
	for i := 0; i < scrollSteps; i++ {
		stepAmount := scrollAmount / float64(scrollSteps)
		// Add variance for human-like imperfect scrolling
		stepAmount += float64(rand.Intn(20) - 10)
		_ = page.Mouse().Wheel(0, stepAmount)
		time.Sleep(time.Duration(10 + rand.Intn(40)) * time.Millisecond)
	}

	return nil
}
