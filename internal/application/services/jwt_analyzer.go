package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"golang.org/x/time/rate"
)

type JWTAnalyzerTool struct{}

func (t *JWTAnalyzerTool) Name() string {
	return "jwt_analyzer"
}

var jwtRegex = regexp.MustCompile(`ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)

func (t *JWTAnalyzerTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		matches := jwtRegex.FindAllString(target, -1)
		if len(matches) == 0 {
			// Also check headers if parsed as context headers
			headers := HeadersFromCtx(ctx)
			for _, v := range headers {
				if m := jwtRegex.FindString(v); m != "" {
					matches = append(matches, m)
				}
			}
		}

		if len(matches) == 0 {
			return nil, nil
		}

		var events []Event
		var mu sync.Mutex

		for _, token := range matches {
			parts := strings.Split(token, ".")
			if len(parts) != 3 {
				continue
			}

			headerDec, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				continue
			}

			payloadDec, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				continue
			}

			var headerJSON map[string]interface{}
			if err := json.Unmarshal(headerDec, &headerJSON); err != nil {
				continue
			}

			var payloadJSON map[string]interface{}
			if err := json.Unmarshal(payloadDec, &payloadJSON); err != nil {
				continue
			}

			alg, _ := headerJSON["alg"].(string)

			// 1. Test None Algorithm
			if strings.ToLower(alg) == "none" || t.testNoneAlg(parts[0], parts[1]) {
				mu.Lock()
				events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "JWT None Algorithm Allowed",
					"severity":    "critical",
					"token":       token,
					"description": "JWT signature verification bypassed using the 'none' algorithm.",
				}, "critical"))
				mu.Unlock()
				slog.Warn("Found JWT vulnerability: None algorithm", "target", target)
				continue
			}

			// 2. Test Weak HS256 Secrets
			if strings.ToUpper(alg) == "HS256" {
				weakSecrets := []string{"secret", "admin", "123456", "password", "jwt", "key", "root"}
				for _, secret := range weakSecrets {
					if t.verifyHS256(parts[0], parts[1], parts[2], secret) {
						mu.Lock()
						events = append(events, NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
							"vuln_name":   "Weak JWT HMAC Secret Key",
							"severity":    "high",
							"secret":      secret,
							"description": fmt.Sprintf("Weak secret key '%s' found verifying JWT HS256 signature.", secret),
						}, "high"))
						mu.Unlock()
						slog.Warn("Found weak JWT secret key", "target", target, "secret", secret)
						break
					}
				}
			}
		}

		return events, nil
	})
}

func (t *JWTAnalyzerTool) testNoneAlg(header, _ string) bool {
	// Simple check if base64 encoded alg field is "none"
	return strings.Contains(strings.ToLower(header), "none")
}

func (t *JWTAnalyzerTool) verifyHS256(header, payload, signature, secret string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(header + "." + payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return expected == signature
}

var _ Tool = (*JWTAnalyzerTool)(nil)
