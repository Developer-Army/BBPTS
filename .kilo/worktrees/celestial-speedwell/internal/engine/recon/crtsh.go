package recon

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	client := &http.Client{}
	for _, target := range targets {
		domain := strings.TrimSpace(target)
		if domain == "" {
			continue
		}
		query := fmt.Sprintf("https://crt.sh/?q=%%25%s&output=json", url.QueryEscape(domain))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, query, nil)
		if err != nil {
			return nil, err
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("crt.sh request failed for %s: %w", domain, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var entries []crtshEntry
		if err := json.Unmarshal(body, &entries); err != nil {
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
			props := map[string]string{"certificate_subject": value}
			events = append(events, NewEvent(value, t.Name(), "subdomain", props))
		}
	}
	return events, nil
}
