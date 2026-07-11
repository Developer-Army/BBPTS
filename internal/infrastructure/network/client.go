package network

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"compress/flate"
	"compress/gzip"

	"github.com/Developer-Army/BBPTS/internal/domain/security"
	"github.com/andybalholm/brotli"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type TLSFingerprint struct {
	ClientHelloID utls.ClientHelloID
	ALPNProtocols []string
	JA3           string // JA3 fingerprint string for identification
}

type BrowserProfile struct {
	Name           string
	UserAgent      string
	TLSFingerprint TLSFingerprint
	HeaderOrder    []string
	AcceptLanguage string
	AcceptEncoding string
}

type StealthClient struct {
	httpClient     *http.Client
	profile        BrowserProfile
	profilePool    []BrowserProfile
	currentProfile int
	rotateAfter    int
	requestCount   int
	mu             sync.RWMutex
	humanTimer     *HumanTimer // optional; if nil, uses fixed jitter
	customHeaders  map[string]string
	proxyPool      []string
	currentProxy   int
	hostBackoff    *PerHostAdaptiveLimiter
}

func NewStealthClient(profile BrowserProfile, proxyURL string) (*StealthClient, error) {
	return NewStealthClientWithPool([]BrowserProfile{profile}, proxyURL)
}

func NewStealthClientWithPool(profiles []BrowserProfile, proxyURL string) (*StealthClient, error) {
	if len(profiles) == 0 {
		return nil, fmt.Errorf("profile pool cannot be empty")
	}

	var proxyPool []string
	if proxyURL != "" {
		for _, p := range strings.Split(proxyURL, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				proxyPool = append(proxyPool, p)
			}
		}
	}

	client := &StealthClient{
		profile:        profiles[0],
		profilePool:    profiles,
		rotateAfter:    50,
		currentProfile: 0,
		humanTimer:     NewHumanTimer(),
		proxyPool:      proxyPool,
		hostBackoff:    NewPerHostAdaptiveLimiter(100, 30000),
	}

	if err := client.buildHTTPClient(); err != nil {
		return nil, err
	}

	return client, nil
}

func (sc *StealthClient) buildHTTPClient() error {
	isProxyAddr := func(addr string) bool {
		sc.mu.RLock()
		defer sc.mu.RUnlock()
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		for _, pStr := range sc.proxyPool {
			u, err := url.Parse(pStr)
			if err == nil {
				pHost := u.Hostname()
				if pHost == host {
					return true
				}
			}
		}
		return false
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {

			if isProxyAddr(addr) {
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			}

			pinnedAddr, _, err := security.ResolveAndValidateAddr(ctx, addr)
			if err != nil {
				return nil, err
			}

			h, _, err := net.SplitHostPort(pinnedAddr)
			if err == nil {
				if addrVal, err := netip.ParseAddr(h); err == nil && security.IsPrivateAddr(addrVal) {
					return nil, fmt.Errorf("SSRF prevention: private IP blocked: %s", h)
				}
			}
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}
			return dialer.DialContext(ctx, network, pinnedAddr)
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS13,
		},
	}

	if len(sc.proxyPool) > 0 {
		transport.Proxy = func(req *http.Request) (*url.URL, error) {
			sc.mu.Lock()
			defer sc.mu.Unlock()
			if len(sc.proxyPool) == 0 {
				return nil, nil
			}
			pStr := sc.proxyPool[sc.currentProxy]
			sc.currentProxy = (sc.currentProxy + 1) % len(sc.proxyPool)
			return url.Parse(pStr)
		}
	}

	profile := sc.profile
	clientHelloID := profile.TLSFingerprint.ClientHelloID
	if clientHelloID == (utls.ClientHelloID{}) {
		clientHelloID = utls.HelloChrome_Auto
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {

		if isProxyAddr(addr) {
			tcpConn, err := net.DialTimeout(network, addr, 30*time.Second)
			if err != nil {
				return nil, err
			}
			uconn := utls.UClient(tcpConn, &utls.Config{
				InsecureSkipVerify: true,
			}, clientHelloID)
			if err := uconn.HandshakeContext(ctx); err != nil {
				tcpConn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}
			return uconn, nil
		}

		pinnedAddr, host, err := security.ResolveAndValidateAddr(ctx, addr)
		if err != nil {
			return nil, err
		}

		h, _, err := net.SplitHostPort(pinnedAddr)
		if err == nil {
			if addrVal, err := netip.ParseAddr(h); err == nil && security.IsPrivateAddr(addrVal) {
				return nil, fmt.Errorf("SSRF prevention: private IP blocked: %s", h)
			}
		}

		tcpConn, err := net.DialTimeout(network, pinnedAddr, 30*time.Second)
		if err != nil {
			return nil, err
		}

		skipVerify := false
		if val := ctx.Value("insecure"); val != nil {
			if b, ok := val.(bool); ok {
				skipVerify = b
			}
		}

		uconn := utls.UClient(tcpConn, &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipVerify,
		}, clientHelloID)

		if err := uconn.HandshakeContext(ctx); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}

		return uconn, nil
	}

	if err := http2.ConfigureTransport(transport); err != nil {
		slog.Warn("Failed to configure HTTP/2 transport on stealth client", "error", err)
	}

	sc.httpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			san := security.NewSanitizer()
			if err := san.ValidateURL(req.URL.String()); err != nil {
				return fmt.Errorf("SSRF validation blocked redirect: %w", err)
			}
			return nil
		},
	}

	return nil
}

func (sc *StealthClient) Do(req *http.Request) (*http.Response, error) {
	sc.mu.Lock()
	sc.requestCount++
	shouldRotate := sc.requestCount%sc.rotateAfter == 0 && len(sc.profilePool) > 1
	if shouldRotate {
		sc.rotateProfile()
	}
	currentProfile := sc.profile
	sc.mu.Unlock()

	sc.applyProfileHeaders(req, currentProfile)

	// Apply host-specific adaptive backoff delay if throttled
	var host string
	var ab *AdaptiveBackoff
	if sc.hostBackoff != nil && req.URL != nil {
		host = req.URL.Hostname()
		ab = sc.hostBackoff.GetBackoff(host)
		if ab.IsThrottled() {
			delay := ab.GetCurrentDelay()
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	if flag.Lookup("test.v") == nil && flag.Lookup("test.run") == nil {
		if sc.humanTimer != nil {
			sc.humanTimer.Sleep()
		} else {

			time.Sleep(time.Duration(20+rand.Intn(80)) * time.Millisecond)
		}
	}

	resp, err := sc.httpClient.Do(req)
	if err != nil {
		if ab != nil {
			ab.RecordBlock()
		}
		return nil, err
	}

	if ab != nil {
		var body []byte
		if resp.StatusCode == http.StatusForbidden && resp.Body != nil {
			body, _ = io.ReadAll(io.LimitReader(resp.Body, 64*1024))
			resp.Body = io.NopCloser(bytes.NewReader(body))
		}
		if ab.ShouldBackoff(resp, body) {
			ab.RecordBlock()
		} else if resp.StatusCode < 400 || (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusForbidden) {
			ab.Reset()
		}
	}

	if resp.Body != nil {
		contentEncoding := resp.Header.Get("Content-Encoding")
		switch strings.ToLower(contentEncoding) {
		case "gzip":
			gr, err := gzip.NewReader(resp.Body)
			if err == nil {
				resp.Body = &decompressedReadCloser{Reader: gr, Original: resp.Body}
				resp.Header.Del("Content-Encoding")
				resp.Header.Del("Content-Length")
				resp.ContentLength = -1
			}
		case "deflate":
			fr := flate.NewReader(resp.Body)
			resp.Body = &decompressedReadCloser{Reader: fr, Original: resp.Body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
		case "br":
			br := brotli.NewReader(resp.Body)
			resp.Body = &decompressedReadCloser{Reader: br, Original: resp.Body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.ContentLength = -1
		}
	}

	return resp, nil
}

type decompressedReadCloser struct {
	Reader   io.Reader
	Original io.ReadCloser
}

func (d *decompressedReadCloser) Read(p []byte) (n int, err error) {
	return d.Reader.Read(p)
}

func (d *decompressedReadCloser) Close() error {
	if rc, ok := d.Reader.(io.ReadCloser); ok {
		_ = rc.Close()
	}
	return d.Original.Close()
}

func (sc *StealthClient) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	return sc.Do(req)
}

func (sc *StealthClient) Post(url string, contentType string, body []byte) (*http.Response, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	req, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, err
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	return sc.Do(req)
}

func (sc *StealthClient) applyProfileHeaders(req *http.Request, profile BrowserProfile) {

	sc.mu.RLock()
	customHeaders := sc.customHeaders
	sc.mu.RUnlock()
	for k, v := range customHeaders {
		req.Header.Set(k, v)
	}

	if profile.UserAgent != "" {
		req.Header.Set("User-Agent", profile.UserAgent)
	}

	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")

	if profile.AcceptLanguage != "" {
		req.Header.Set("Accept-Language", profile.AcceptLanguage)
	} else {
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	}

	if profile.AcceptEncoding != "" {
		req.Header.Set("Accept-Encoding", profile.AcceptEncoding)
	} else {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}

	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")

	req.Header.Set("Cache-Control", "max-age=0")

	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	if len(profile.HeaderOrder) > 0 {
		sc.reorderHeaders(req, profile.HeaderOrder)
	}
}

func (sc *StealthClient) rotateProfile() {
	sc.currentProfile = (sc.currentProfile + 1) % len(sc.profilePool)
	sc.profile = sc.profilePool[sc.currentProfile]
	slog.Debug("Rotated browser profile", "profile", sc.profile.Name, "request_count", sc.requestCount)

	if err := sc.buildHTTPClient(); err != nil {
		slog.Warn("Failed to rebuild HTTP client with new profile", "error", err)
	}
}

func (sc *StealthClient) reorderHeaders(req *http.Request, order []string) {
	headers := make(map[string]string)
	for k, v := range req.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}

	req.Header = http.Header{}

	for _, key := range order {
		if val, ok := headers[key]; ok {
			req.Header.Set(key, val)
			delete(headers, key)
		}
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
}

func (sc *StealthClient) GetProfile() BrowserProfile {
	return sc.profile
}

func (sc *StealthClient) SetCustomHeaders(headers map[string]string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.customHeaders = headers
}

func (sc *StealthClient) GetRequestCount() int {
	return sc.requestCount
}

func (sc *StealthClient) Close() error {
	if sc.httpClient != nil {
		sc.httpClient.CloseIdleConnections()
	}
	return nil
}

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
