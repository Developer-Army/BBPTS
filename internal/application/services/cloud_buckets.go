package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

type CloudBucketsTool struct{}

func (t *CloudBucketsTool) Name() string {
	return "cloud_buckets"
}

var cloudBucketsClient *http.Client

func (t *CloudBucketsTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Generate bucket name candidates from root domains
	var candidates []string
	seen := make(map[string]struct{})
	suffixes := []string{
		"", "-backup", "-assets", "-public", "-private", "-staging", "-prod", "-dev",
		"-static", "-media", "-logs", "-data", "backup", "assets", "public",
	}

	for _, target := range targets {
		// Clean target to get the main label
		domain := strings.TrimSpace(strings.ToLower(target))
		if strings.Contains(domain, "://") {
			parts := strings.Split(domain, "://")
			if len(parts) > 1 {
				domain = parts[1]
			}
		}
		if idx := strings.Index(domain, "/"); idx != -1 {
			domain = domain[:idx]
		}
		// Extract first segment or domain name
		parts := strings.Split(domain, ".")
		if len(parts) > 0 && parts[0] != "" {
			name := parts[0]
			for _, suffix := range suffixes {
				candidate := name + suffix
				if len(candidate) >= 3 && len(candidate) <= 63 { // S3 bucket length constraints
					if _, ok := seen[candidate]; !ok {
						seen[candidate] = struct{}{}
						candidates = append(candidates, candidate)
					}
				}
			}
		}
	}

	if len(candidates) == 0 {
		return nil, nil
	}

	slog.Info("Probing cloud buckets for target candidates...", "candidates_count", len(candidates))

	var events []Event
	var eventsMu sync.Mutex

	// Semaphore/concurrency control
	if threads < 1 {
		threads = 10
	}
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	client := cloudBucketsClient
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // Don't follow redirects to keep responses clean
			},
		}
	}

	for _, name := range candidates {
		// AWS S3
		wg.Add(1)
		go func(bucket string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			url := fmt.Sprintf("https://%s.s3.amazonaws.com", bucket)
			t.probeBucket(ctx, client, url, "aws", bucket, &events, &eventsMu)
		}(name)

		// Google Cloud Storage (GCS)
		wg.Add(1)
		go func(bucket string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			url := fmt.Sprintf("https://storage.googleapis.com/%s", bucket)
			t.probeBucket(ctx, client, url, "gcs", bucket, &events, &eventsMu)
		}(name)

		// Azure Blob Storage
		wg.Add(1)
		go func(bucket string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			url := fmt.Sprintf("https://%s.blob.core.windows.net", bucket)
			t.probeBucket(ctx, client, url, "azure", bucket, &events, &eventsMu)
		}(name)
	}

	wg.Wait()
	return events, nil
}

func (t *CloudBucketsTool) probeBucket(ctx context.Context, client *http.Client, url, provider, bucket string, events *[]Event, mu *sync.Mutex) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	// If 200 OK, the bucket is publicly listable
	if resp.StatusCode == http.StatusOK {
		// Read a small prefix of the body to check for XML list bucket result
		bodyBytes := make([]byte, 1024)
		n, _ := resp.Body.Read(bodyBytes)
		bodyStr := string(bodyBytes[:n])

		isPublicList := false
		if provider == "aws" && (strings.Contains(bodyStr, "ListBucketResult") || strings.Contains(bodyStr, "ListAllMyBucketsResult")) {
			isPublicList = true
		} else if provider == "gcs" && strings.Contains(bodyStr, "ListBucketResult") {
			isPublicList = true
		} else if provider == "azure" && (strings.Contains(bodyStr, "EnumerationResults") || resp.Header.Get("Content-Type") == "application/xml") {
			isPublicList = true
		} else if provider == "azure" && resp.StatusCode == 200 { // Azure sometimes has list disable but allows checking
			isPublicList = true
		}

		if isPublicList {
			mu.Lock()
			*events = append(*events, NewEvent(url, t.Name(), "vulnerability", map[string]string{
				"provider":    provider,
				"bucket":      bucket,
				"severity":    "critical",
				"vuln_name":   "Publicly Accessible Cloud Storage Bucket",
				"description": fmt.Sprintf("The %s cloud storage bucket '%s' is publicly listable and readable.", strings.ToUpper(provider), bucket),
			}))
			mu.Unlock()
			slog.Warn("Found open cloud bucket", "provider", provider, "bucket", bucket, "url", url)
		}
	} else if resp.StatusCode == http.StatusForbidden && provider == "aws" {
		// Bucket exists but Access Denied (still useful intelligence, but not a critical finding)
		mu.Lock()
		*events = append(*events, NewEvent(url, t.Name(), "discovery", map[string]string{
			"provider":    provider,
			"bucket":      bucket,
			"severity":    "info",
			"vuln_name":   "Private Cloud Storage Bucket Discovered",
			"description": fmt.Sprintf("The AWS bucket '%s' exists but access is forbidden.", bucket),
		}))
		mu.Unlock()
	}
}

// Make sure it implements Tool interface
var _ Tool = (*CloudBucketsTool)(nil)
