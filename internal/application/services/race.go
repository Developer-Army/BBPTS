package services

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type RaceTool struct{}

func (t *RaceTool) Name() string {
	return "race"
}

func (t *RaceTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 30
	}

	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	stateChangingKeywords := []string{
		"coupon", "redeem", "giftcard", "payment", "checkout", "transfer",
		"reset", "apply", "use", "withdraw", "add", "increment", "vote",
	}

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]Event, error) {
		target = strings.TrimSpace(target)
		if target == "" || !strings.HasPrefix(target, "http") {
			return nil, nil
		}

		// Heuristic: only test endpoints matching state-changing keywords to minimize noise/traffic
		targetLower := strings.ToLower(target)
		isStateChanging := false
		for _, kw := range stateChangingKeywords {
			if strings.Contains(targetLower, kw) {
				isStateChanging = true
				break
			}
		}

		if !isStateChanging {
			isStateChanging = t.looksStateChangingByResponse(ctx, target)
		}

		if !isStateChanging {
			return nil, nil
		}

		// Run race condition test
		hasRace, successCount, err := t.testRace(ctx, target)
		if err != nil {
			return nil, nil
		}

		var events []Event
		if hasRace {
			events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":       "Race Condition Vulnerability",
				"severity":        "high",
				"success_count":   fmt.Sprintf("%d", successCount),
				"description":     fmt.Sprintf("Multiple concurrent state-changing requests (%d successes) succeeded on %s, suggesting a race condition.", successCount, target),
			}, "high"))
		}

		return events, nil
	})
}

func (t *RaceTool) looksStateChangingByResponse(ctx context.Context, target string) bool {
	client := NewSafeHTTPClient(5 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewBuffer([]byte("{}")))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for k, v := range HeadersFromCtx(ctx) {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	bodyLower := strings.ToLower(string(body))
	for _, marker := range []string{"success", "applied", "used", "redeemed"} {
		if strings.Contains(bodyLower, marker) {
			return true
		}
	}
	return false
}

func (t *RaceTool) testRace(ctx context.Context, target string) (bool, int, error) {
	numRequests := 15
	var wg sync.WaitGroup
	barrier := make(chan struct{})
	
	type reqResult struct {
		statusCode int
		err        error
	}
	results := make([]reqResult, numRequests)
	
	client := NewSafeHTTPClient(10 * time.Second)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			// Prepare request
			// We try POST first as it is standard for state-changing, fallback to GET if needed
			req, err := http.NewRequestWithContext(ctx, "POST", target, bytes.NewBuffer([]byte("{}")))
			if err != nil {
				results[idx] = reqResult{err: err}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")

			headers := HeadersFromCtx(ctx)
			for k, v := range headers {
				req.Header.Set(k, v)
			}

			// Wait for the release barrier
			<-barrier

			resp, err := client.Do(req)
			if err != nil {
				results[idx] = reqResult{err: err}
				return
			}
			defer resp.Body.Close()

			results[idx] = reqResult{statusCode: resp.StatusCode}
		}(i)
	}

	// Release all request goroutines at once
	close(barrier)
	wg.Wait()

	successCount := 0
	for _, res := range results {
		if res.err == nil && (res.statusCode == http.StatusOK || res.statusCode == http.StatusCreated || res.statusCode == http.StatusNoContent) {
			successCount++
		}
	}

	// Heuristic: If we sent 15 concurrent requests, and more than 1 succeeded, it indicates a race condition
	// (usually, only 1 request like coupon application should succeed, others should conflict/fail with 4xx/5xx).
	if successCount > 1 {
		return true, successCount, nil
	}

	return false, successCount, nil
}

var _ Tool = (*RaceTool)(nil)
