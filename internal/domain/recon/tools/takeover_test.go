package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"
)

func TestTakeoverTool(t *testing.T) {
	// Set up mock HTTP client to return simulated takeover responses
	takeoverHttpClient = &http.Client{
		Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {
			// If it's a request to sub.github.io or vulnerable subdomain
			if req.URL.Host == "vulnerable.com" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("There is no page here")),
					Header:     make(http.Header),
				}, nil
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString("Safe content")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() {
		takeoverHttpClient = nil
	}()

	tool := &TakeoverTool{}
	if tool.Name() != "takeover" {
		t.Errorf("Expected tool name 'takeover', got %s", tool.Name())
	}

	// Note: Testing with a real CNAME lookup would fail in isolated environments,
	// but we can test the signature logic. In general, LookupCNAME will fail
	// for dummy hosts, so the test will check empty/no-takeover scenarios or mock results.
	// Let's verify that a host with no CNAME resolves safely.
	targets := []string{"nonexistent-subdomain-12345.com"}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, targets, 2)
	if err != nil {
		t.Fatalf("Unexpected error running takeover tool: %v", err)
	}

	if len(events) != 0 {
		t.Errorf("Expected 0 events for nonexistent subdomain, got %d", len(events))
	}
}
