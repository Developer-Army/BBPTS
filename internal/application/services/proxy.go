// Package services provides application services for reconnaissance
package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// ProxyFeeder sends requests through a specified proxy to warm up tools like Burp or Caido.
type ProxyFeeder struct {
	ProxyURL   string
	httpClient *http.Client
}

// NewProxyFeeder creates a ProxyFeeder.
func NewProxyFeeder(proxyURL string) (*ProxyFeeder, error) {
	if proxyURL == "" {
		return nil, fmt.Errorf("proxy URL cannot be empty")
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	transport := &http.Transport{
		Proxy:           http.ProxyURL(u),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
	}

	return &ProxyFeeder{
		ProxyURL: proxyURL,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			// Do not follow redirects so we see the original response in the proxy
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// FeedURLs sends requests for all given URLs through the proxy concurrently.
func (pf *ProxyFeeder) FeedURLs(ctx context.Context, urls []string, concurrency int) {
	if concurrency <= 0 {
		concurrency = 5
	}

	slog.Info("proxy feeder: starting", "urls", len(urls), "proxy", pf.ProxyURL)

	jobs := make(chan string, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				pf.feedURL(ctx, u)
			}
		}()
	}

	for _, u := range urls {
		jobs <- u
	}
	close(jobs)
	wg.Wait()

	slog.Info("proxy feeder: complete")
}

func (pf *ProxyFeeder) feedURL(ctx context.Context, u string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		slog.Debug("proxy feeder: request creation failed", "url", u, "error", err)
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; BBPTS-ProxyFeeder/1.0)")

	// We don't really care about the response body, just that it passed through the proxy
	resp, err := pf.httpClient.Do(req)
	if err != nil {
		slog.Debug("proxy feeder: request failed", "url", u, "error", err)
		return
	}
	defer resp.Body.Close()

	slog.Debug("proxy feeder: fed", "url", u, "status", resp.StatusCode)
}
