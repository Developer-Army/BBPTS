package tools

import (
	"bytes"
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net/http"
	"testing"
)

type mockRoundTripper func(req *http.Request) (*http.Response, error)

func (f mockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestCloudBucketsTool(t *testing.T) {

	cloudBucketsClient = &http.Client{
		Transport: mockRoundTripper(func(req *http.Request) (*http.Response, error) {

			if req.URL.Host == "target-assets.s3.amazonaws.com" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("<ListBucketResult><Name>target-assets</Name></ListBucketResult>")),
					Header:     make(http.Header),
				}, nil
			}

			if req.URL.Host == "storage.googleapis.com" && req.URL.Path == "/target" {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(bytes.NewBufferString("<ListBucketResult><Name>target</Name></ListBucketResult>")),
					Header:     make(http.Header),
				}, nil
			}

			if req.URL.Host == "target-private.s3.amazonaws.com" {
				return &http.Response{
					StatusCode: http.StatusForbidden,
					Body:       io.NopCloser(bytes.NewBufferString("Access Denied")),
					Header:     make(http.Header),
				}, nil
			}

			return &http.Response{
				StatusCode: http.StatusNotFound,
				Body:       io.NopCloser(bytes.NewBufferString("Not Found")),
				Header:     make(http.Header),
			}, nil
		}),
	}
	defer func() {
		cloudBucketsClient = nil
	}()

	tool := &CloudBucketsTool{}
	if tool.Name() != "cloud_buckets" {
		t.Errorf("Expected tool name 'cloud_buckets', got %s", tool.Name())
	}

	targets := []string{"target.com"}
	events, err := tool.Run(context.Background(), &recon.ScanContext{}, targets, 2)
	if err != nil {
		t.Fatalf("Unexpected error running cloud buckets tool: %v", err)
	}

	foundS3Public := false
	foundGCSPublic := false
	foundS3Private := false

	for _, ev := range events {
		if ev.Source != "cloud_buckets" {
			t.Errorf("Expected source 'cloud_buckets', got %s", ev.Source)
		}
		if ev.Properties["bucket"] == "target-assets" && ev.Properties["provider"] == "aws" && ev.Properties["severity"] == "critical" {
			foundS3Public = true
		}
		if ev.Properties["bucket"] == "target" && ev.Properties["provider"] == "gcs" && ev.Properties["severity"] == "critical" {
			foundGCSPublic = true
		}
		if ev.Properties["bucket"] == "target-private" && ev.Properties["provider"] == "aws" && ev.Properties["severity"] == "info" {
			foundS3Private = true
		}
	}

	if !foundS3Public {
		t.Error("Expected to find public S3 bucket 'target-assets'")
	}
	if !foundGCSPublic {
		t.Error("Expected to find public GCS bucket 'target'")
	}
	if !foundS3Private {
		t.Error("Expected to find private S3 bucket 'target-private'")
	}
}
