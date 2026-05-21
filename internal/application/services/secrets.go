package services

import (
	"context"
	"io"
	"math/rand"
	"net/http"
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
	"shodan_key":   regexp.MustCompile(`[a-zA-Z0-9]{32}`), // Heuristic
}

func (t *SecretsTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := []Event{}
	var mu sync.Mutex
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	proxies := GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[rand.Intn(len(proxies))]
	}
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	client, _ := network.NewStealthClient(profile, proxy)

	for _, target := range targets {
		if !strings.HasSuffix(target, ".js") && !strings.Contains(target, ".json") {
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

			body, _ := io.ReadAll(resp.Body)
			content := string(body)

			for name, re := range secretPatterns {
				matches := re.FindAllString(content, -1)
				for _, match := range matches {
					mu.Lock()
					events = append(events, NewEvent(u, t.Name(), "secret_exposed", map[string]string{
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
