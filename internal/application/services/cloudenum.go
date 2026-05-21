package services

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
)

type CloudEnumTool struct{}

func (t *CloudEnumTool) Name() string {
	return "cloudenum"
}

func (t *CloudEnumTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
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

	platforms := []string{
		"s3.amazonaws.com",
		"blob.core.windows.net",
		"storage.googleapis.com",
		"digitaloceanspaces.com",
	}

	for _, target := range targets {
		base := strings.Split(target, ".")[0]
		for _, platform := range platforms {
			wg.Add(1)
			go func(b, p string) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}

				bucketURL := fmt.Sprintf("https://%s.%s", b, p)
				req, _ := http.NewRequestWithContext(ctx, "HEAD", bucketURL, nil)
				resp, err := client.Do(req)
				if err == nil {
					if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusForbidden {
						mu.Lock()
						events = append(events, NewEvent(bucketURL, t.Name(), "cloud_bucket", map[string]string{
							"platform": p,
							"status":   fmt.Sprintf("%d", resp.StatusCode),
						}))
						mu.Unlock()
					}
					resp.Body.Close()
				}
			}(base, platform)
		}
	}

	wg.Wait()
	return events, nil
}
