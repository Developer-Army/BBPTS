package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

type AppStoreReconTool struct{}

func (t *AppStoreReconTool) Name() string { return "app_store_recon" }

type iTunesApp struct {
	TrackID          int64    `json:"trackId"`
	TrackName        string   `json:"trackName"`
	BundleID         string   `json:"bundleId"`
	Version          string   `json:"version"`
	MinimumOSVersion string   `json:"minimumOsVersion"`
	SellerName       string   `json:"sellerName"`
	Description      string   `json:"description"`
	GenreName        string   `json:"primaryGenreName"`
	Features         []string `json:"features"`
	Advisories       []string `json:"advisories"`
	SupportURL       string   `json:"supportUrl"`
	PrivacyPolicyURL string   `json:"privacyPolicyUrl"`
	ArtistURL        string   `json:"artistUrl"`
}

type iTunesResponse struct {
	Results []iTunesApp `json:"results"`
}

var urlExtractRe = regexp.MustCompile(`https?://[a-zA-Z0-9._/-]+`)
var apiExtractRe = regexp.MustCompile(`https?://[a-zA-Z0-9._-]+/(?:api|v[0-9]+)[a-zA-Z0-9._/-]*`)

func (t *AppStoreReconTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	maxThreads := threads
	if scanCtx.LowResource {
		if maxThreads > 2 {
			maxThreads = 2
		}
	} else if maxThreads > 4 {
		maxThreads = 4
	}

	events := []recon.Event{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxThreads)

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		wg.Add(1)
		go func(tgt string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			evts, err := t.reconTarget(ctx, scanCtx, tgt)
			if err != nil {
				slog.Debug("app_store_recon: failed", "target", tgt, "error", err)
				return
			}
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *AppStoreReconTool) reconTarget(ctx context.Context, scanCtx *recon.ScanContext, target string) ([]recon.Event, error) {
	events := []recon.Event{}

	lower := strings.ToLower(target)
	switch {
	case strings.Contains(lower, "apple.com") || strings.Contains(lower, "itunes") || isNumericID(target):
		evts, err := t.searchApple(ctx, scanCtx, target)
		if err != nil {
			return nil, err
		}
		events = append(events, evts...)

	case strings.Contains(lower, "play.google.com") || strings.Contains(lower, "market://"):
		evts := t.searchGooglePlay(ctx, scanCtx, target)
		events = append(events, evts...)

	default:
		ev, err := t.searchApple(ctx, scanCtx, target)
		if err == nil {
			events = append(events, ev...)
		}
		gp := t.searchGooglePlay(ctx, scanCtx, target)
		events = append(events, gp...)
	}

	if len(events) == 0 {
		events = append(events, recon.NewEvent(target, t.Name(), "discovery", map[string]string{
			"scan_type": "app_store_recon",
			"query":     target,
			"note":      "no results found",
		}))
	}

	return events, nil
}

func (t *AppStoreReconTool) searchApple(ctx context.Context, scanCtx *recon.ScanContext, query string) ([]recon.Event, error) {
	events := []recon.Event{}

	apiURL := fmt.Sprintf("https://itunes.apple.com/search?term=%s&entity=software&limit=3", url.QueryEscape(query))

	client := NewSafeHTTPClient(15 * time.Second)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}
	headers := scanCtx.Headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	qg := scanCtx.QuotaGuard
	if qg != nil {
		qg.Increment("apple_store")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, err
	}

	var result iTunesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	for _, app := range result.Results {
		props := map[string]string{
			"store":     "apple",
			"app_id":    fmt.Sprintf("%d", app.TrackID),
			"name":      app.TrackName,
			"developer": app.SellerName,
			"bundle_id": app.BundleID,
			"version":   app.Version,
			"min_os":    app.MinimumOSVersion,
			"category":  app.GenreName,
			"scan_type": "app_store_recon",
		}
		events = append(events, recon.NewEvent(app.BundleID, t.Name(), "discovery", props))

		for _, u := range extractURLs(app.Description) {
			events = append(events, recon.NewEvent(u, t.Name(), "discovery", map[string]string{
				"app_id": app.BundleID, "store": "apple", "scan_type": "app_store_recon",
			}))
		}

		for _, ep := range extractAPIEndpoints(app.Description) {
			events = append(events, recon.NewEvent(ep, t.Name(), "api_endpoint", map[string]string{
				"app_id": app.BundleID, "store": "apple", "scan_type": "app_store_recon",
			}))
		}

		if app.SupportURL != "" {
			events = append(events, recon.NewEvent(app.SupportURL, t.Name(), "discovery", map[string]string{
				"type": "support_url", "app_id": app.BundleID, "scan_type": "app_store_recon",
			}))
		}
	}

	return events, nil
}

func (t *AppStoreReconTool) searchGooglePlay(ctx context.Context, scanCtx *recon.ScanContext, query string) []recon.Event {
	events := []recon.Event{}

	packageName := query
	if strings.Contains(query, "play.google.com") {
		re := regexp.MustCompile(`id=([a-zA-Z0-9.]+)`)
		if m := re.FindStringSubmatch(query); len(m) > 1 {
			packageName = m[1]
		}
	}

	apiURL := fmt.Sprintf("https://play.google.com/store/apps/details?id=%s&hl=en", url.QueryEscape(packageName))

	client := NewSafeHTTPClient(15 * time.Second)
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return events
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	headers := scanCtx.Headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	qg := scanCtx.QuotaGuard
	if qg != nil {
		qg.Increment("google_play")
	}

	resp, err := client.Do(req)
	if err != nil {
		return events
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return events
	}
	bodyStr := string(body)

	props := map[string]string{
		"store":     "google_play",
		"bundle_id": packageName,
		"scan_type": "app_store_recon",
	}

	if m := regexp.MustCompile(`<title>([^<]+)</title>`).FindStringSubmatch(bodyStr); len(m) > 1 {
		props["name"] = strings.TrimSuffix(m[1], " - Google Play")
	}
	if m := regexp.MustCompile(`"versionName":"([^"]+)"`).FindStringSubmatch(bodyStr); len(m) > 1 {
		props["version"] = m[1]
	}
	if m := regexp.MustCompile(`"developer":"([^"]+)"`).FindStringSubmatch(bodyStr); len(m) > 1 {
		props["developer"] = m[1]
	}

	events = append(events, recon.NewEvent(packageName, t.Name(), "discovery", props))

	permRe := regexp.MustCompile(`android\.permission\.([A-Z_]+)`)
	for _, p := range permRe.FindAllString(bodyStr, -1) {
		events = append(events, recon.NewEvent(packageName, t.Name(), "discovery", map[string]string{
			"permission": p, "platform": "android", "scan_type": "app_store_recon",
		}))
	}

	for _, u := range extractURLs(bodyStr) {
		events = append(events, recon.NewEvent(u, t.Name(), "discovery", map[string]string{
			"app_id": packageName, "store": "google_play", "scan_type": "app_store_recon",
		}))
	}

	return events
}

func extractURLs(text string) []string {
	seen := map[string]bool{}
	var urls []string
	for _, u := range urlExtractRe.FindAllString(text, -1) {
		u = strings.TrimRight(u, ".,;:!?)")
		if !seen[u] && len(u) > 15 {
			seen[u] = true
			urls = append(urls, u)
		}
	}
	return urls
}

func extractAPIEndpoints(text string) []string {
	seen := map[string]bool{}
	var eps []string
	for _, ep := range apiExtractRe.FindAllString(text, -1) {
		ep = strings.TrimRight(ep, ".,;:!?)\"'")
		if !seen[ep] && len(ep) > 15 {
			seen[ep] = true
			eps = append(eps, ep)
		}
	}
	return eps
}

func isNumericID(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}
