package tools

import (
	"bufio"
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type MobileAPIDiscoveryTool struct{}

func (t *MobileAPIDiscoveryTool) Name() string { return "mobile_api_discovery" }

var apiURLRe = []*regexp.Regexp{
	regexp.MustCompile(`https?://[a-zA-Z0-9._-]+\.(?:com|io|net|dev|app|co)(?:/[a-zA-Z0-9._/\-{}]*)?`),
	regexp.MustCompile(`/api/v[0-9]+/[a-zA-Z0-9._/-]+`),
	regexp.MustCompile(`/v[0-9]+/[a-zA-Z0-9._/-]+`),
}

var apiHeaderRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"(?:x-api-key|x-auth-token|x-access-token)":\s*"([^"]+)"`),
	regexp.MustCompile(`(?i)(?:Authorization|Bearer|Basic)\s+([a-zA-Z0-9._\-]+=*)`),
}

var apiEndpointRe = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:url|endpoint|base_url|baseURL|api_url|host|server)\s*[:=]\s*["']([^"']+)["']`),
	regexp.MustCompile(`(?i)(?:fetch|axios|http\.get|http\.post|request)\s*\(\s*["']([^"']+)["']`),
}

func (t *MobileAPIDiscoveryTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

			evts := t.discover(ctx, scanCtx, tgt)
			mu.Lock()
			events = append(events, evts...)
			mu.Unlock()
		}(target)
	}

	wg.Wait()
	return events, nil
}

func (t *MobileAPIDiscoveryTool) discover(ctx context.Context, scanCtx *recon.ScanContext, target string) []recon.Event {
	switch {
	case strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://"):
		return t.scanURL(ctx, scanCtx, target)
	case isBinaryPath(target):
		return t.scanBinary(target)
	case strings.Contains(target, "."):
		return t.probeDomain(ctx, scanCtx, target)
	default:
		return t.generalRecon(target)
	}
}

func (t *MobileAPIDiscoveryTool) scanURL(ctx context.Context, scanCtx *recon.ScanContext, appURL string) []recon.Event {
	events := []recon.Event{}

	client := NewSafeHTTPClient(20 * time.Second)
	req, err := http.NewRequestWithContext(ctx, "GET", appURL, nil)
	if err != nil {
		return events
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)")
	headers := scanCtx.Headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	qg := scanCtx.QuotaGuard
	if qg != nil {
		qg.Increment("http_probe")
	}

	resp, err := client.Do(req)
	if err != nil {
		return events
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 256*1024), 512*1024)

	seen := map[string]bool{}

	for scanner.Scan() {
		line := scanner.Text()

		for _, p := range apiURLRe {
			for _, m := range p.FindAllString(line, -1) {
				if seen[m] || len(m) > 300 {
					continue
				}
				seen[m] = true
				events = append(events, recon.NewEvent(m, t.Name(), "api_endpoint", map[string]string{
					"url":       m,
					"source":    "url_content",
					"scan_type": "mobile_api_discovery",
				}))
			}
		}

		for _, p := range apiHeaderRe {
			for _, m := range p.FindAllStringSubmatch(line, -1) {
				if len(m) > 1 && !seen[m[1]] {
					seen[m[1]] = true
					events = append(events, recon.NewEvent(appURL, t.Name(), "secret_exposed", map[string]string{
						"header":    m[1],
						"source":    "url_content",
						"severity":  "medium",
						"scan_type": "mobile_api_discovery",
					}))
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Error("mobile_api_discovery: scanner error during url scan", "error", err)
	}

	return events
}

func (t *MobileAPIDiscoveryTool) scanBinary(path string) []recon.Event {
	events := []recon.Event{}

	f, err := os.Open(path)
	if err != nil {
		return events
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 512*1024)

	seen := map[string]bool{}
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, p := range apiURLRe {
			for _, m := range p.FindAllString(line, -1) {
				if seen[m] || len(m) > 300 {
					continue
				}
				seen[m] = true
				conf := "low"
				if strings.Contains(m, "/api/") || strings.Contains(m, "/v1/") {
					conf = "high"
				} else if strings.HasPrefix(m, "https://") {
					conf = "medium"
				}
				events = append(events, recon.NewEvent(m, t.Name(), "api_endpoint", map[string]string{
					"url":        m,
					"line":       fmt.Sprintf("%d", lineNum),
					"confidence": conf,
					"scan_type":  "mobile_api_discovery",
				}))
			}
		}

		for _, p := range apiEndpointRe {
			for _, m := range p.FindAllStringSubmatch(line, -1) {
				if len(m) > 1 && !seen[m[1]] && len(m[1]) > 5 {
					seen[m[1]] = true
					events = append(events, recon.NewEvent(m[1], t.Name(), "api_endpoint", map[string]string{
						"url":       m[1],
						"line":      fmt.Sprintf("%d", lineNum),
						"source":    "binary_code",
						"scan_type": "mobile_api_discovery",
					}))
				}
			}
		}

		for _, p := range apiHeaderRe {
			for _, m := range p.FindAllStringSubmatch(line, -1) {
				if len(m) > 1 && !seen[m[1]] {
					seen[m[1]] = true
					events = append(events, recon.NewEvent(path, t.Name(), "secret_exposed", map[string]string{
						"header":    m[1],
						"line":      fmt.Sprintf("%d", lineNum),
						"severity":  "medium",
						"scan_type": "mobile_api_discovery",
					}))
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		slog.Error("mobile_api_discovery: scanner error during binary scan", "error", err)
	}

	return events
}

func (t *MobileAPIDiscoveryTool) probeDomain(ctx context.Context, scanCtx *recon.ScanContext, domain string) []recon.Event {
	events := []recon.Event{}

	if !strings.HasPrefix(domain, "http") {
		domain = "https://" + domain
	}

	paths := []string{"/api", "/api/v1", "/graphql", "/rest", "/swagger", "/health", "/config"}

	client := NewSafeHTTPClient(8 * time.Second)

	for _, p := range paths {
		select {
		case <-ctx.Done():
			return events
		default:
		}

		targetURL := strings.TrimRight(domain, "/") + p
		req, err := http.NewRequestWithContext(ctx, "HEAD", targetURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0")

		qg := scanCtx.QuotaGuard
		if qg != nil {
			qg.Increment("http_probe")
		}

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 401 || resp.StatusCode == 403 {
			events = append(events, recon.NewEvent(targetURL, t.Name(), "api_endpoint", map[string]string{
				"url":           targetURL,
				"status":        fmt.Sprintf("%d", resp.StatusCode),
				"requires_auth": fmt.Sprintf("%t", resp.StatusCode != 200),
				"scan_type":     "mobile_api_discovery",
			}))
		}
	}

	return events
}

func (t *MobileAPIDiscoveryTool) generalRecon(target string) []recon.Event {
	return []recon.Event{recon.NewEvent(target, t.Name(), "discovery", map[string]string{
		"scan_type": "mobile_api_recon",
		"target":    target,
		"note":      "passive recon mode",
	})}
}

func isBinaryPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	return ext == ".ipa" || ext == ".apk" || ext == ".zip"
}
