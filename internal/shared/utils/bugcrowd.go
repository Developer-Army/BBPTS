package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

// BugcrowdClient handles API submissions to Bugcrowd.
type BugcrowdClient struct {
	Token   string
	Program string
}

// NewBugcrowdClient creates a new client from environment variables.
func NewBugcrowdClient(program string) *BugcrowdClient {
	return &BugcrowdClient{
		Token:   os.Getenv("BBPTS_BUGCROWD_API_TOKEN"),
		Program: program,
	}
}

// IsConfigured returns true if API credentials are provided.
func (b *BugcrowdClient) IsConfigured() bool {
	return b.Token != "" && b.Program != ""
}

// SubmitReport creates a submission on Bugcrowd.
func (b *BugcrowdClient) SubmitReport(title, description, severity string) error {
	if !b.IsConfigured() {
		return fmt.Errorf("bugcrowd credentials not configured")
	}

	// Bugcrowd Crowdcontrol API v1
	url := "https://api.bugcrowd.com/submissions"

	payload := map[string]interface{}{
		"submission": map[string]interface{}{
			"program":     b.Program,
			"title":       title,
			"description": description,
			"severity":    severity,
		},
	}

	body, _ := json.Marshal(payload)
	req, err := newJSONRequest(http.MethodPost, url, body)
	if err != nil {
		return err
	}

	// Bugcrowd uses Token auth
	req.Header.Set("Authorization", "Token "+b.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.bugcrowd.v4+json")

	resp, err := doWithRetry(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		apiBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("bugcrowd API error: %s: %s", resp.Status, string(apiBody))
	}

	slog.Info("Successfully submitted report to Bugcrowd", "title", title)
	return nil
}
