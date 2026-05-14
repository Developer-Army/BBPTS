package services

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type ShodanTool struct{}

type shodanResult struct {
	IP       string `json:"ip_str"`
	Port     int    `json:"port"`
	Protocol string `json:"_shodan.module"`
	Product  string `json:"product"`
	Version  string `json:"version"`
	Title    string `json:"title"`
	Banner   string `json:"data"`
	Org      string `json:"org"`
	ISP      string `json:"isp"`
	Country  string `json:"country_name"`
}

type shodanResponse struct {
	Matches []shodanResult `json:"matches"`
	Total   int            `json:"total"`
}

func (t *ShodanTool) Name() string {
	return "shodan"
}

func (t *ShodanTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	apiKey := GetAPIKey(ctx, "shodan")
	if apiKey == "" {
		slog.Debug("Shodan API key not configured, skipping")
		return nil, nil
	}

	events := make([]Event, 0)

	for _, target := range targets {
		// Parse target (domain or IP)
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		host := strings.TrimSpace(target)
		if host == "" {
			continue
		}

		// Call Shodan host search API
		url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?query=%s&key=%s&limit=10", host, apiKey)
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			slog.Debug("Failed to create Shodan request", "error", err)
			continue
		}

		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			slog.Debug("Shodan API request failed", "host", host, "error", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			io.ReadAll(resp.Body)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		var shodanResp shodanResponse
		if err := json.Unmarshal(body, &shodanResp); err != nil {
			slog.Debug("Failed to parse Shodan response", "error", err)
			continue
		}

		for _, match := range shodanResp.Matches {
			target := fmt.Sprintf("%s:%d", match.IP, match.Port)
			props := map[string]string{
				"protocol": match.Protocol,
				"product":  match.Product,
				"version":  match.Version,
				"title":    match.Title,
				"org":      match.Org,
				"country":  match.Country,
			}
			if match.ISP != "" {
				props["isp"] = match.ISP
			}
			events = append(events, NewEvent(target, t.Name(), "service", props))
		}
	}

	return events, nil
}
