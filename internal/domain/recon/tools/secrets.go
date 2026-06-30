package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
)

type SecretsTool struct{}

func (t *SecretsTool) Name() string {
	return "secrets"
}

var secretPatterns = map[string]*regexp.Regexp{
	"aws_key":      regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"google_api":   regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),
	"firebase_url": regexp.MustCompile(`[a-z0-9.-]+\.firebaseio\.com`),
	"slack_token":  regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
	"github_token": regexp.MustCompile(`gh[pso]_[a-zA-Z0-9]{36}`),
	"stripe_key":   regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
}

func (t *SecretsTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := []recon.Event{}
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	proxies := recon.GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	client, err := network.NewStealthClient(profile, proxy)
	if err != nil || client == nil {
		return nil, fmt.Errorf("failed to create stealth client: %w", err)
	}
	client.SetCustomHeaders(scanCtx.Headers)

	for _, target := range targets {
		parsedTarget, err := url.Parse(target)
		if err != nil {
			continue
		}
		pathLower := strings.ToLower(parsedTarget.Path)
		if !strings.HasSuffix(pathLower, ".js") && !strings.Contains(pathLower, ".json") {
			continue
		}

		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			body, _ := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
			content := string(body)

			for name, re := range secretPatterns {
				matches := re.FindAllString(content, -1)
				for _, match := range matches {
					mu.Lock()
					events = append(events, recon.NewEvent(u, t.Name(), "secret_exposed", map[string]string{
						"type":   name,
						"secret": match,
					}))
					mu.Unlock()
				}
			}
		}(target)
	}

	wg.Wait()
	return events, nil
}
