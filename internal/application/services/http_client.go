package services

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"time"

	utls "github.com/refraction-networking/utls"
)

// StealthClient provides an http.Client that mimics a real browser's TLS signature
// to avoid detection by WAFs like Cloudflare and Akamai.
type StealthClient struct {
	client *http.Client
	jitter time.Duration
}

// NewStealthClient creates a new HTTP client configured for evasion.
func NewStealthClient(proxy string, maxJitter time.Duration) (*StealthClient, error) {
	// Custom dialer using utls for TLS fingerprint spoofing (mimics Chrome)
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		conn, err := net.DialTimeout(network, addr, 10*time.Second)
		if err != nil {
			return nil, err
		}

		uConn := utls.UClient(conn, &utls.Config{ServerName: host, InsecureSkipVerify: true}, utls.HelloChrome_Auto)
		if err := uConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("utls handshake failed: %w", err)
		}
		return uConn, nil
	}

	transport := &http.Transport{
		DialTLSContext:        dialTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Add proxy if provided
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return &StealthClient{
		client: client,
		jitter: maxJitter,
	}, nil
}

// Do executes an HTTP request, optionally adding random jitter delay beforehand.
func (sc *StealthClient) Do(req *http.Request) (*http.Response, error) {
	classifier := NewErrorClassifier()
	var lastErr error
	var resp *http.Response

	maxRetries := 3
	backoff := 1 * time.Second

	for i := 0; i < maxRetries; i++ {
		if sc.jitter > 0 {
			delay := time.Duration(rand.Int63n(int64(sc.jitter)))
			time.Sleep(delay)
		}

		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
		}
		if req.Header.Get("Accept") == "" {
			req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
		}
		if req.Header.Get("Accept-Language") == "" {
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		}

		resp, lastErr = sc.client.Do(req)

		class := classifier.Classify(resp, lastErr)
		if class == ClassSuccess || class == ClassUnknown {
			return resp, lastErr
		}

		if class == ClassDeadHost {
			return resp, lastErr // No point retrying a dead host immediately
		}

		// Intelligent handling
		if class == ClassWAFBlock || class == ClassCaptcha {
			// Identity rotation logic would go here. For now, we rotate the UA slightly.
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			backoff = backoff * 2 // Slow down
		}

		if class == ClassRateLimited {
			backoff = backoff * 3 // Exponential backoff
		}

		if resp != nil && class != ClassSuccess {
			resp.Body.Close()
		}

		time.Sleep(backoff)
	}

	return resp, lastErr
}

// Get is a wrapper around client.Get with stealth capabilities
func (sc *StealthClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return sc.Do(req)
}
