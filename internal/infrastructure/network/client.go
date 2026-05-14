package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLSFingerprint represents a browser TLS fingerprint configuration.
type TLSFingerprint struct {
	ClientHelloID utls.ClientHelloID
	ALPNProtocols []string
	JA3           string // JA3 fingerprint string for identification
}

// BrowserProfile represents a complete browser fingerprint profile.
type BrowserProfile struct {
	Name           string
	UserAgent      string
	TLSFingerprint TLSFingerprint
	HeaderOrder    []string
	AcceptLanguage string
	AcceptEncoding string
}

// StealthClient is an HTTP client with browser fingerprinting capabilities.
type StealthClient struct {
	httpClient     *http.Client
	profile        BrowserProfile
	profilePool    []BrowserProfile
	currentProfile int
	rotateAfter    int
	requestCount   int
	mu             sync.RWMutex
	humanTimer     *HumanTimer // optional; if nil, uses fixed jitter
}

// NewStealthClient creates a new stealth HTTP client with TLS fingerprinting.
// Uses a single profile (no rotation).
func NewStealthClient(profile BrowserProfile, proxyURL string) (*StealthClient, error) {
	return NewStealthClientWithPool([]BrowserProfile{profile}, proxyURL)
}

// NewStealthClientWithPool creates a stealth client with a pool of browser profiles for rotation.
func NewStealthClientWithPool(profiles []BrowserProfile, proxyURL string) (*StealthClient, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("profile pool cannot be empty")
	}

	client := &StealthClient{
		profile:        profiles[0],
		profilePool:    profiles,
		rotateAfter:    50,
		currentProfile: 0,
		humanTimer:     NewHumanTimer(), // enable human-like timing by default
	}

	if err := client.buildHTTPClient(); err != nil {
		return nil, err
	}

	return client, nil
}

// NOTE: Duplicate NewStealthClientWithPool was removed — the primary definition
// with humanTimer initialization (above) is the canonical one.

// buildHTTPClient constructs the HTTP client with TLS fingerprinting.
func (sc *StealthClient) buildHTTPClient() error {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		},
	}

	// Use uTLS for TLS fingerprinting based on current profile
	profile := sc.profile
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		tcpConn, err := net.DialTimeout(network, addr, 30*time.Second)
		if err != nil {
			return nil, err
		}

		// Extract hostname
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		uconn := utls.UClient(tcpConn, &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: false,
		}, profile.TLSFingerprint.ClientHelloID)

		if err := uconn.Handshake(); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		return uconn, nil
	}

	sc.httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return nil
}

// Do performs an HTTP request with stealth headers and fingerprinting.
func (sc *StealthClient) Do(req *http.Request) (*http.Response, error) {
	sc.mu.Lock()
	sc.requestCount++
	shouldRotate := sc.requestCount%sc.rotateAfter == 0 && len(sc.profilePool) > 1
	if shouldRotate {
		sc.rotateProfile()
	}
	currentProfile := sc.profile
	sc.mu.Unlock()

	// Apply browser profile headers
	sc.applyProfileHeaders(req, currentProfile)

	// Apply human-like timing
	if sc.humanTimer != nil {
		sc.humanTimer.Sleep()
	} else {
		// Fallback: fixed jitter
		time.Sleep(time.Duration(20+rand.Intn(80)) * time.Millisecond)
	}

	return sc.httpClient.Do(req)
}

// Get performs a GET request with stealth.
func (sc *StealthClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return sc.Do(req)
}

// Post performs a POST request with stealth.
func (sc *StealthClient) Post(url string, contentType string, body []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	if body != nil {
		req.Body = nil // Would need to set up a reader
	}

	return sc.Do(req)
}

// applyProfileHeaders applies browser-specific headers to the request.
func (sc *StealthClient) applyProfileHeaders(req *http.Request, profile BrowserProfile) {
	// Set User-Agent
	if profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	// Set Accept
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

	// Set Accept-Language
	if profile.AcceptLanguage != "" {
		req.Header.Set("Accept-Language", profile.AcceptLanguage)
	} else {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	// Set Accept-Encoding
	if profile.AcceptEncoding != "" {
		req.Header.Set("Accept-Encoding", profile.AcceptEncoding)
	} else {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	// Sec-Fetch headers (modern browsers)
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	// Cache-Control
	req.Header.Set("Cache-Control", "max-age=0")

	// DNT and Connection
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// Apply header order if specified
	if len(profile.HeaderOrder) > 0 {
		sc.reorderHeaders(req, profile.HeaderOrder)
	}
}

// rotateProfile rotates to the next browser profile in the pool.
func (sc *StealthClient) rotateProfile() {
	sc.currentProfile = (sc.currentProfile + 1) % len(sc.profilePool)
	sc.profile = sc.profilePool[sc.currentProfile]
	slog.Debug("Rotated browser profile", "profile", sc.profile.Name, "request_count", sc.requestCount)

	// Rebuild HTTP client with new TLS fingerprint
	if err := sc.buildHTTPClient(); err != nil {
		slog.Warn("Failed to rebuild HTTP client with new profile", "error", err)
	}
}

// reorderHeaders reorders request headers to match browser behavior.
func (sc *StealthClient) reorderHeaders(req *http.Request, order []string) {
	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	// Clear existing headers
	req.Header = http.Header{}

	// Add headers in specified order
	for _, key := range order {
		if val, ok := headers[key]; ok {
			req.Header.Set(key, val)
			delete(headers, key)
		}
	}

	// Add remaining headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

// GetProfile returns the current browser profile.
func (sc *StealthClient) GetProfile() BrowserProfile {
	return sc.profile
}

// GetRequestCount returns the total number of requests made.
func (sc *StealthClient) GetRequestCount() int {
	return sc.requestCount
}

// Close closes the stealth client and cleans up resources.
func (sc *StealthClient) Close() error {
	if sc.httpClient != nil {
		sc.httpClient.CloseIdleConnections()
	}
	return nil
}

// DefaultBrowserProfiles returns a set of common browser fingerprints.
func DefaultBrowserProfiles() []BrowserProfile {
	return []BrowserProfile{
		{
			Name:      "Chrome-Auto-Windows",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			TLSFingerprint: TLSFingerprint{
				ClientHelloID: utls.HelloChrome_Auto,
				ALPNProtocols: []string{"h2", "http/1.1"},
			},
			HeaderOrder:    []string{"Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"},
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
		},
		{
			Name:      "Firefox-Auto-Windows",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
			TLSFingerprint: TLSFingerprint{
				ClientHelloID: utls.HelloFirefox_Auto,
				ALPNProtocols: []string{"h2", "http/1.1"},
			},
			HeaderOrder:    []string{"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding", "Connection", "Upgrade-Insecure-Requests"},
			AcceptLanguage: "en-US,en;q=0.5",
			AcceptEncoding: "gzip, deflate, br",
		},
		{
			Name:      "Chrome-Auto-Mac",
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			TLSFingerprint: TLSFingerprint{
				ClientHelloID: utls.HelloChrome_Auto,
				ALPNProtocols: []string{"h2", "http/1.1"},
			},
			HeaderOrder:    []string{"Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"},
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
		},
		{
			Name:      "Safari-Auto-Mac",
			UserAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
			TLSFingerprint: TLSFingerprint{
				ClientHelloID: utls.HelloSafari_Auto,
				ALPNProtocols: []string{"h2", "http/1.1"},
			},
			HeaderOrder:    []string{"Host", "Connection", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding"},
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
		},
		{
			Name:      "Edge-Auto-Windows",
			UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
			TLSFingerprint: TLSFingerprint{
				ClientHelloID: utls.HelloChrome_Auto,
				ALPNProtocols: []string{"h2", "http/1.1"},
			},
			HeaderOrder:    []string{"Host", "Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest", "Accept-Encoding", "Accept-Language"},
			AcceptLanguage: "en-US,en;q=0.9",
			AcceptEncoding: "gzip, deflate, br",
		},
	}
}
