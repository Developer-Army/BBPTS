package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
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
	{
		Name:     "Webflow",
		CNameSub: "webflow.com",
		Response: []string{"The page you are looking for doesn't exist", "404 Not Found"},
	},
	{
		Name:     "Zendesk",
		CNameSub: "zendesk.com",
		Response: []string{"No such Web Portal", "Help Center Closed"},
	},
	{
		Name:     "WP Engine",
		CNameSub: "wpengine.com",
		Response: []string{"The site you were looking for could not be found"},
	},
	{
		Name:     "Pantheon",
		CNameSub: "pantheonsite.io",
		Response: []string{"The route has not been registered", "404 error"},
	},
	{
		Name:     "Tumblr",
		CNameSub: "tumblr.com",
		Response: []string{"Whatever you were looking for doesn't exist"},
	},
	{
		Name:     "Ghost",
		CNameSub: "ghost.io",
		Response: []string{"The thing you're looking for is no longer here"},
	},
	{
		Name:     "Squarespace",
		CNameSub: "squarespace.com",
		Response: []string{"Domain Not Claimed", "mapped to Squarespace"},
	},
	{
		Name:     "Readme.io",
		CNameSub: "readmessl.com",
		Response: []string{"Project doesn't exist"},
	},
	{
		Name:     "Bitbucket",
		CNameSub: "bitbucket.io",
		Response: []string{"Repository not found"},
	},
	{
		Name:     "Cargo",
		CNameSub: "cargo.site",
		Response: []string{"404 Not Found", "This site is private", "domain is not yet configured"},
	},
	{
		Name:     "WordPress",
		CNameSub: "wordpress.com",
		Response: []string{"Domain mapping upgrade for this domain not found", "Do you want to register"},
	},
}

var takeoverHttpClient *http.Client

func (t *TakeoverTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	slog.Info("Running Subdomain Takeover Scanner...", "targets_count", len(targets))

	var events []recon.Event
	var mu sync.Mutex
	var dnsCache sync.Map

	if threads < 1 {
		threads = 10
	}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	client := takeoverHttpClient
	if client == nil {
		safeClient := NewSafeHTTPClient(5 * time.Second)
		safeClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
		client = safeClient
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

			// Perform DNS CNAME lookup with cache
			var cname string
			var err error
			if cachedVal, ok := dnsCache.Load(cleanHost); ok {
				cname = cachedVal.(string)
			} else {
				cname, err = net.LookupCNAME(cleanHost)
				if err != nil {
					return
				}
				cname = strings.ToLower(cname)
				dnsCache.Store(cleanHost, cname)
			}

			for _, sig := range takeoverSignatures {
				if strings.Contains(cname, sig.CNameSub) {
					// Check HTTP responses
					schemes := []string{"http", "https"}
					for _, scheme := range schemes {
						url := fmt.Sprintf("%s://%s", scheme, cleanHost)
						var resp *http.Response
						cfg := RetryConfig{
							MaxRetries:     2,
							BaseDelay:      1 * time.Second,
							MaxDelay:       5 * time.Second,
							Multiplier:     2.0,
							JitterFraction: 0.2,
						}
						errRetry := ExecuteWithRetry(ctx, cfg, func(ctx context.Context, attempt int) (bool, error) {
							req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
							if err != nil {
								return false, err
							}
							headers := scanCtx.Headers
							for k, v := range headers {
								req.Header.Set(k, v)
							}
							r, err := client.Do(req)
							if err != nil {
								return true, err
							}
							resp = r
							return false, nil
						})
						if errRetry != nil {
							continue
						}
						bodyBytes, _ := io.ReadAll(resp.Body)
						resp.Body.Close()
						bodyStr := string(bodyBytes)

						for _, rStr := range sig.Response {
							if strings.Contains(bodyStr, rStr) {
								mu.Lock()
								events = append(events, recon.NewEvent(url, t.Name(), "vulnerability", map[string]string{
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
var _ recon.Tool = (*TakeoverTool)(nil)
