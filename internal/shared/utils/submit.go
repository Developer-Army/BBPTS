package utils

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type Platform interface {
	IsConfigured() bool
	SubmitReport(title, description, severity string) error
}

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

var defaultHTTPClient httpDoer = &http.Client{Timeout: 30 * time.Second}

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

			resp.Body.Close()
		} else {
			lastErr = err
		}

		if attempt < 3 {
			delays := []time.Duration{250 * time.Millisecond, 500 * time.Millisecond}
			time.Sleep(delays[attempt-1])
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

func AutoSubmit(platformName, program, title, description, severity string) error {
	slog.Info("[DRY-RUN] AutoSubmit finding (real submissions disabled to protect account)",
		"platform", platformName,
		"program", program,
		"title", title,
		"severity", severity,
	)
	return nil
}
