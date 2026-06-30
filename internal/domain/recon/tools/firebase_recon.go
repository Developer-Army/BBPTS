package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type FirebaseReconTool struct{}

func (t *FirebaseReconTool) Name() string {
	return "firebase_recon"
}

var (
	firebaseProjectRegex    = regexp.MustCompile(`(?i)projectId["']?\s*:\s*["']([a-zA-Z0-9\-]{4,30})["']`)
	firebaseStorageRegex    = regexp.MustCompile(`(?i)storageBucket["']?\s*:\s*["']([a-zA-Z0-9\-\.]{4,60})["']`)
	firebaseDatabaseRegex   = regexp.MustCompile(`(?i)databaseURL["']?\s*:\s*["'](https?://[a-zA-Z0-9\-\.]+firebaseio\.com)["']`)
	firebaseStorageURLRegex = regexp.MustCompile(`(?i)firebasestorage\.googleapis\.com/v0/b/([a-zA-Z0-9\-\.]{4,60})`)

	amplifyUserPoolRegex = regexp.MustCompile(`(?i)aws_user_pools_id["']?\s*:\s*["']([a-zA-Z0-9\-_]{4,40})["']`)
	amplifyGraphQLRegex  = regexp.MustCompile(`(?i)aws_appsync_graphqlEndpoint["']?\s*:\s*["'](https?://[a-zA-Z0-9\-\.]+\.appsync\-api\.[a-zA-Z0-9\-]+\.amazonaws\.com/graphql)["']`)
	amplifyS3BucketRegex = regexp.MustCompile(`(?i)aws_user_files_s3_bucket["']?\s*:\s*["']([a-zA-Z0-9\-\.]{3,60})["']`)
)

func (t *FirebaseReconTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

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
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
		resp.Body.Close()

		bodyStr := string(bodyBytes)

		var events []recon.Event
		var mu sync.Mutex

		projectIDs := make(map[string]bool)
		storageBuckets := make(map[string]bool)
		rtdbURLs := make(map[string]bool)

		cognitoPools := make(map[string]bool)
		graphqlEndpoints := make(map[string]bool)
		amplifyS3Buckets := make(map[string]bool)

		if m := firebaseProjectRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
			projectIDs[m[1]] = true
		}
		if m := firebaseStorageRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
			bucket := strings.TrimSuffix(m[1], ".appspot.com")
			storageBuckets[bucket] = true
		}
		if m := firebaseDatabaseRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
			rtdbURLs[m[1]] = true
		}
		if m := firebaseStorageURLRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
			bucket := strings.TrimSuffix(m[1], ".appspot.com")
			storageBuckets[bucket] = true
		}
		if m := amplifyUserPoolRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
			cognitoPools[m[1]] = true
		}
		if m := amplifyGraphQLRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
			graphqlEndpoints[m[1]] = true
		}
		if m := amplifyS3BucketRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
			amplifyS3Buckets[m[1]] = true
		}

		parsed, err := url.Parse(target)
		if err == nil {
			host := parsed.Hostname()
			if strings.Contains(host, ".firebaseapp.com") || strings.Contains(host, ".web.app") {
				parts := strings.Split(host, ".")
				if len(parts) > 2 {
					projectIDs[parts[0]] = true
				}
			}
		}

		for rtdb := range rtdbURLs {
			jsonURL := rtdb
			if !strings.HasSuffix(jsonURL, "/") {
				jsonURL += "/"
			}
			jsonURL += ".json"

			tReq, err := http.NewRequestWithContext(ctx, "GET", jsonURL, nil)
			if err != nil {
				continue
			}
			tResp, err := client.Do(tReq)
			if err == nil {
				tBody, _ := io.ReadAll(io.LimitReader(tResp.Body, 1024))
				tResp.Body.Close()
				if tResp.StatusCode == 200 && !strings.Contains(string(tBody), "Permission denied") && len(tBody) > 2 {
					mu.Lock()
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "Firebase RTDB Unauthenticated Read",
						"severity":    "critical",
						"database":    rtdb,
						"evidence":    string(tBody),
						"description": fmt.Sprintf("Firebase Realtime Database exposes unauthenticated read access at %s", jsonURL),
					}, "critical"))
					mu.Unlock()
				}
			}
		}

		for pid := range projectIDs {

			rtdbURL := fmt.Sprintf("https://%s.firebaseio.com/.json", pid)
			tReq, err := http.NewRequestWithContext(ctx, "GET", rtdbURL, nil)
			if err != nil {
				continue
			}
			tResp, err := client.Do(tReq)
			if err == nil {
				tBody, _ := io.ReadAll(io.LimitReader(tResp.Body, 1024))
				tResp.Body.Close()
				if tResp.StatusCode == 200 && !strings.Contains(string(tBody), "Permission denied") && len(tBody) > 2 {
					mu.Lock()
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "Firebase RTDB Unauthenticated Read",
						"severity":    "critical",
						"database":    pid,
						"evidence":    string(tBody),
						"description": fmt.Sprintf("Firebase Realtime Database exposes unauthenticated read access at %s", rtdbURL),
					}, "critical"))
					mu.Unlock()
				}
			}

			firestoreURL := fmt.Sprintf("https://firestore.googleapis.com/v1/projects/%s/databases/(default)/documents", pid)
			fReq, err := http.NewRequestWithContext(ctx, "GET", firestoreURL, nil)
			if err == nil {
				fResp, err := client.Do(fReq)
				if err == nil {
					fBody, _ := io.ReadAll(io.LimitReader(fResp.Body, 1024))
					fResp.Body.Close()
					if fResp.StatusCode == 200 && len(fBody) > 2 && !strings.Contains(string(fBody), "PERMISSION_DENIED") {
						mu.Lock()
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Firebase Firestore Public Rules Exposed",
							"severity":    "high",
							"project_id":  pid,
							"evidence":    string(fBody),
							"description": fmt.Sprintf("Cloud Firestore allows unauthenticated document listing at %s", firestoreURL),
						}, "high"))
						mu.Unlock()
					}
				}
			}

			hostingURL := fmt.Sprintf("https://%s.web.app/__/firebase/init.json", pid)
			hReq, err := http.NewRequestWithContext(ctx, "GET", hostingURL, nil)
			if err == nil {
				hResp, err := client.Do(hReq)
				if err == nil {
					hBody, _ := io.ReadAll(io.LimitReader(hResp.Body, 2048))
					hResp.Body.Close()
					if hResp.StatusCode == 200 {
						mu.Lock()
						events = append(events, recon.NewEvent(target, t.Name(), "discovery", map[string]string{
							"type":        "firebase_config",
							"project_id":  pid,
							"url":         hostingURL,
							"config_json": string(hBody),
						}))
						mu.Unlock()
					}
				}
			}
		}

		for bucket := range storageBuckets {
			storageURL := fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s.appspot.com/o", bucket)
			tReq, err := http.NewRequestWithContext(ctx, "GET", storageURL, nil)
			if err != nil {
				continue
			}
			tResp, err := client.Do(tReq)
			if err == nil {
				tBody, _ := io.ReadAll(io.LimitReader(tResp.Body, 1024))
				tResp.Body.Close()
				if tResp.StatusCode == 200 && len(tBody) > 2 && !strings.Contains(string(tBody), "could not be authorized") {
					mu.Lock()
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   "Firebase Storage Public Listing",
						"severity":    "high",
						"bucket":      bucket,
						"evidence":    string(tBody),
						"description": fmt.Sprintf("Firebase Storage bucket exposes public file listing at %s", storageURL),
					}, "high"))
					mu.Unlock()
				}
			}
		}

		for gql := range graphqlEndpoints {

			qReq, err := http.NewRequestWithContext(ctx, "POST", gql, strings.NewReader(`{"query":"query { __schema { queryType { name } } }"}`))
			if err == nil {
				qReq.Header.Set("Content-Type", "application/json")
				qResp, err := client.Do(qReq)
				if err == nil {
					qBody, _ := io.ReadAll(io.LimitReader(qResp.Body, 1024))
					qResp.Body.Close()
					if qResp.StatusCode == 200 && strings.Contains(string(qBody), "queryType") {
						mu.Lock()
						events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Unauthenticated AWS AppSync GraphQL Access",
							"severity":    "high",
							"endpoint":    gql,
							"evidence":    string(qBody),
							"description": fmt.Sprintf("Amplify AppSync GraphQL endpoint allows unauthenticated schema queries at %s", gql),
						}, "high"))
						mu.Unlock()
					}
				}
			}
		}

		for pool := range cognitoPools {
			mu.Lock()
			events = append(events, recon.NewEvent(target, t.Name(), "discovery", map[string]string{
				"type":         "amplify_cognito_pool",
				"user_pool_id": pool,
			}))
			mu.Unlock()
		}

		for bucket := range amplifyS3Buckets {
			mu.Lock()
			events = append(events, recon.NewEvent(target, t.Name(), "discovery", map[string]string{
				"type":      "amplify_s3_bucket",
				"s3_bucket": bucket,
			}))
			mu.Unlock()
		}

		return events, nil
	})
}

var _ recon.Tool = (*FirebaseReconTool)(nil)
