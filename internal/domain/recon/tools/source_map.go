package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type SourceMapTool struct{}

func (t *SourceMapTool) Name() string {
	return "source_map"
}

type sourceMapJSON struct {
	Version        interface{} `json:"version"`
	Sources        []string    `json:"sources"`
	SourcesContent []string    `json:"sourcesContent"`
}

var (
	sourceMapSecrets = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(?:api[_-]?key|apikey|secret|client[_-]?secret|password|passwd|token|access[_-]?token)\s*[:=]\s*["']([^"']{8,})["']`),
		regexp.MustCompile(`(?i)(?:aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*["']?(AKIA[0-9A-Z]{16})["']?`),
		regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*["']([^"']{40})["']`),
	}
	sourceMapEndpoints = regexp.MustCompile(`['"](/api/[a-zA-Z0-9_/\-{}:.]+)['"]`)
	sourceMapComments  = regexp.MustCompile(`(?i)//\s*(TODO|FIXME|debug|test|security|bypass|credentials|password|auth|login)`)
)

func (t *SourceMapTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		client := NewSafeHTTPClient(10 * time.Second)

		// 1. Fetch JS bundle to check for sourceMappingURL or check directly for .map URL
		var mapURLs []string
		if strings.HasSuffix(target, ".map") {
			mapURLs = append(mapURLs, target)
		} else if strings.HasSuffix(target, ".js") {
			// Try directly appending .map
			mapURLs = append(mapURLs, target+".map")

			// Also try fetching the JS to find sourceMappingURL
			req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
			if err == nil {
				for k, v := range scanCtx.Headers {
					req.Header.Set(k, v)
				}
				resp, err := client.Do(req)
				if err == nil {
					bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
					resp.Body.Close()
					bodyStr := string(bodyBytes)

					// search for sourceMappingURL=...
					idx := strings.LastIndex(bodyStr, "sourceMappingURL=")
					if idx != -1 {
						val := bodyStr[idx+len("sourceMappingURL="):]
						val = strings.TrimSpace(val)
						if end := strings.IndexAny(val, "\r\n "); end != -1 {
							val = val[:end]
						}
						// resolve relative URL
						base, err := url.Parse(target)
						if err == nil {
							ref, err := url.Parse(val)
							if err == nil {
								mapURLs = append(mapURLs, base.ResolveReference(ref).String())
							}
						}
					}
				}
			}
		} else {
			// Not a JS/map file, skip
			return nil, nil
		}

		var events []recon.Event
		var mu sync.Mutex
		seen := make(map[string]bool)

		for _, mapURL := range mapURLs {
			if seen[mapURL] {
				continue
			}
			seen[mapURL] = true

			req, err := http.NewRequestWithContext(ctx, "GET", mapURL, nil)
			if err != nil {
				continue
			}
			for k, v := range scanCtx.Headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // limit to 10MB
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				continue
			}

			var sm sourceMapJSON
			if err := json.Unmarshal(bodyBytes, &sm); err != nil {
				continue
			}

			// If it's a valid source map, emit a discovery event first
			mu.Lock()
			events = append(events, recon.NewEvent(mapURL, t.Name(), "discovery", map[string]string{
				"type":          "source_map",
				"sources_count": fmt.Sprintf("%d", len(sm.Sources)),
				"detail":        fmt.Sprintf("Discovered public source map containing %d files", len(sm.Sources)),
			}))
			mu.Unlock()

			// Parse original sourcesContent
			for i, content := range sm.SourcesContent {
				if i >= len(sm.Sources) {
					break
				}
				sourceFile := sm.Sources[i]

				// Scan for secrets
				for _, r := range sourceMapSecrets {
					matches := r.FindAllStringSubmatch(content, -1)
					for _, m := range matches {
						val := m[1]
						mu.Lock()
						events = append(events, recon.NewEventWithSeverity(mapURL, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Exposed Secret in Source Map",
							"severity":    "high",
							"file":        sourceFile,
							"evidence":    m[0],
							"description": fmt.Sprintf("Hardcoded secret/credential found in source map file %s: %s", sourceFile, val),
						}, "high"))
						mu.Unlock()
					}
				}

				// Scan for internal endpoints
				endpoints := sourceMapEndpoints.FindAllStringSubmatch(content, -1)
				for _, ep := range endpoints {
					mu.Lock()
					events = append(events, recon.NewEvent(ep[1], t.Name(), "api_endpoint", map[string]string{
						"source": mapURL,
						"file":   sourceFile,
					}))
					mu.Unlock()
				}

				// Scan for debug / TODO comments referencing security
				comments := sourceMapComments.FindAllStringSubmatch(content, -1)
				for _, comm := range comments {
					mu.Lock()
					events = append(events, recon.NewEvent(mapURL, t.Name(), "discovery", map[string]string{
						"type":        "source_map_comment",
						"file":        sourceFile,
						"keyword":     comm[1],
						"description": fmt.Sprintf("Developer comment found in %s: %s", sourceFile, comm[0]),
					}))
					mu.Unlock()
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*SourceMapTool)(nil)
