package utils

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// Platform defines the interface for bug bounty platform API clients.
type Platform interface {
	IsConfigured() bool
	SubmitReport(title, description, severity string) error
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

var defaultHTTPClient httpDoer = &http.Client{Timeout: 30 * time.Second}

// SetHTTPClient swaps the HTTP client used by submitters and returns a restore function.
// It is intended for tests.
func SetHTTPClient(client httpDoer) func() {
	previous := defaultHTTPClient
	defaultHTTPClient = client
	return func() {
		defaultHTTPClient = previous
	}
}

func doWithRetry(req *http.Request) (*http.Response, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		cloned := req.Clone(req.Context())
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			cloned.Body = body
		}

		resp, err := defaultHTTPClient.Do(cloned)
		if err == nil && resp.StatusCode < 500 {
			return resp, nil
		}
		if err == nil {
			lastErr = fmt.Errorf("server returned %s", resp.Status)
			_ = resp.Body.Close()
		} else {
			lastErr = err
		}

		if attempt < 3 {
			time.Sleep(time.Duration(1<<uint(attempt-1)) * 250 * time.Millisecond)
		}
	}
	return nil, lastErr
}

func newJSONRequest(method, url string, payload []byte) (*http.Request, error) {
	req, err := http.NewRequest(method, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(payload)), nil
	}
	return req, nil
}

// AutoSubmit iterates through configured platforms and submits the report.
func AutoSubmit(platformName, program, title, description, severity string) error {
	var platform Platform

	switch strings.ToLower(platformName) {
	case "hackerone":
		platform = NewHackerOneClient(program)
	case "bugcrowd":
		platform = NewBugcrowdClient(program)
	default:
		slog.Warn("Unsupported bug bounty platform for auto-submit", "platform", platformName)
		return nil
	}

	if !platform.IsConfigured() {
		slog.Debug("Auto-submit skipped: credentials not configured", "platform", platformName)
		return nil
	}

	return platform.SubmitReport(title, description, severity)
}
