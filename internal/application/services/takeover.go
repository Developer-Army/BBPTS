package services

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type TakeoverTool struct{}

func (t *TakeoverTool) Name() string {
	return "takeover"
}

type takeoverSig struct {
	Name     string
	CNameSub string
	Response []string
}

var takeoverSignatures = []takeoverSig{
	{
		Name:     "GitHub Pages",
		CNameSub: "github.io",
		Response: []string{"There is no page here", "404 Not Found"},
	},
	{
		Name:     "Heroku",
		CNameSub: "herokuapp.com",
		Response: []string{"no such app", "herokucdn.com"},
	},
	{
		Name:     "Shopify",
		CNameSub: "myshopify.com",
		Response: []string{"Sorry, this shop is currently unavailable", "Only one Step Left"},
	},
	{
		Name:     "Amazon S3",
		CNameSub: "s3.amazonaws.com",
		Response: []string{"NoSuchBucket", "The specified bucket does not exist"},
	},
	{
		Name:     "Cloudfront",
		CNameSub: "cloudfront.net",
		Response: []string{"Bad Gateway: CloudFront", "The request could not be satisfied"},
	},
}

var takeoverHttpClient *http.Client

func (t *TakeoverTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	slog.Info("Running Subdomain Takeover Scanner...", "targets_count", len(targets))

	var events []Event
	var mu sync.Mutex

	if threads < 1 {
		threads = 10
	}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	client := takeoverHttpClient
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	for _, target := range targets {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			// Clean hostname
			cleanHost := host
			if strings.Contains(cleanHost, "://") {
				parts := strings.Split(cleanHost, "://")
				if len(parts) > 1 {
					cleanHost = parts[1]
				}
			}
			if idx := strings.Index(cleanHost, "/"); idx != -1 {
				cleanHost = cleanHost[:idx]
			}
			if idx := strings.Index(cleanHost, ":"); idx != -1 {
				cleanHost = cleanHost[:idx]
			}

			// Perform DNS CNAME lookup
			cname, err := net.LookupCNAME(cleanHost)
			if err != nil {
				return
			}
			cname = strings.ToLower(cname)

			for _, sig := range takeoverSignatures {
				if strings.Contains(cname, sig.CNameSub) {
					// Check HTTP responses
					schemes := []string{"http", "https"}
					for _, scheme := range schemes {
						url := fmt.Sprintf("%s://%s", scheme, cleanHost)
						req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
						if err != nil {
							continue
						}
						resp, err := client.Do(req)
						if err != nil {
							continue
						}
						bodyBytes, _ := io.ReadAll(resp.Body)
						resp.Body.Close()
						bodyStr := string(bodyBytes)

						for _, rStr := range sig.Response {
							if strings.Contains(bodyStr, rStr) {
								mu.Lock()
								events = append(events, NewEvent(url, t.Name(), "vulnerability", map[string]string{
									"vuln_name":   "Subdomain Takeover",
									"severity":    "high",
									"cname":       cname,
									"service":     sig.Name,
									"description": fmt.Sprintf("Subdomain takeover possible on '%s' pointing to '%s' (%s).", cleanHost, cname, sig.Name),
								}))
								mu.Unlock()
								slog.Warn("Subdomain takeover vulnerability detected", "host", cleanHost, "service", sig.Name, "cname", cname)
								return
							}
						}
					}
				}
			}
		}(target)
	}

	wg.Wait()
	return events, nil
}

// Make sure it implements Tool interface
var _ Tool = (*TakeoverTool)(nil)
