package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

// HackerOneClient handles API submissions to HackerOne.
type HackerOneClient struct {
	Username string
	Token    string
	Program  string
}

// NewHackerOneClient creates a new client from environment variables.
func NewHackerOneClient(program string) *HackerOneClient {
	return &HackerOneClient{
		Username: os.Getenv("BBPTS_H1_USER"),
		Token:    os.Getenv("BBPTS_H1_API_TOKEN"),
		Program:  program,
	}
}

// IsConfigured returns true if API credentials are provided.
func (h *HackerOneClient) IsConfigured() bool {
	return h.Username != "" && h.Token != "" && h.Program != ""
}

// SubmitReport creates a draft report on HackerOne.
func (h *HackerOneClient) SubmitReport(title, description, severity string) error {
	if !h.IsConfigured() {
		return fmt.Errorf("hackerone credentials not configured")
	}

	url := "https://api.hackerone.com/v1/reports"

	payload := map[string]interface{}{
		"data": map[string]interface{}{
			"type": "report",
			"attributes": map[string]interface{}{
				"team_handle":               h.Program,
				"title":                     title,
				"vulnerability_information": description,
				"severity_rating":           severity,
				"state":                     "new",
			},
		},
	}

	body, _ := json.Marshal(payload)
	req, err := newJSONRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}

	req.SetBasicAuth(h.Username, h.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		apiBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("hackerone API error: %s: %s", resp.Status, string(apiBody))
	}

	slog.Info("Successfully submitted report to HackerOne", "title", title)
	return nil
}
