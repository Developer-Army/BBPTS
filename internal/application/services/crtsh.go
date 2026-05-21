package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
)

type CrtshTool struct{}

type crtshEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func (t *CrtshTool) Name() string {
	return "crtsh"
}

func (t *CrtshTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	events := []Event{}
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
	var hadAttempt bool
	var lastErr error
	for _, target := range targets {
		domain := strings.TrimSpace(target)
		if domain == "" {
			continue
		}
		hadAttempt = true
		query := fmt.Sprintf("https://crt.sh/?q=%%25%s&output=json", url.QueryEscape(domain))

		var body []byte
		var err error
		for i := 0; i < 3; i++ {
			req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, query, nil)
			if reqErr != nil {
				return nil, reqErr
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

			resp, doErr := client.Do(req)
			if doErr != nil {
				err = doErr
				time.Sleep(2 * time.Second)
				continue
			}

			if resp.StatusCode != http.StatusOK {
				resp.Body.Close()
				err = fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
				time.Sleep(2 * time.Second)
				continue
			}

			body, err = io.ReadAll(resp.Body)
			resp.Body.Close()
			if err == nil {
				break
			}
			time.Sleep(1 * time.Second)
		}

		if err != nil {
			lastErr = err
			continue
		}

		var entries []crtshEntry
		if err := json.Unmarshal(body, &entries); err != nil {
			lastErr = err
			continue
		}
		for _, item := range entries {
			value := item.NameValue
			if value == "" {
				value = item.CommonName
			}
			if value == "" {
				continue
			}
			for _, line := range strings.Split(value, "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				// Clean up wildcard results
				line = strings.TrimPrefix(line, "*.")
				props := map[string]string{"certificate_subject": line}
				events = append(events, NewEvent(line, t.Name(), "subdomain", props))
			}
		}
	}
	if len(events) == 0 && hadAttempt && lastErr != nil {
		return nil, fmt.Errorf("crt.sh produced no results: %w", lastErr)
	}
	return events, nil
}
