package network

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AdaptiveBackoff implements intelligent backoff for 429, CAPTCHA, and WAF blocks.
type AdaptiveBackoff struct {
	baseDelayMs       int
	maxDelayMs        int
	currentDelayMs    int
	consecutiveErrors int
	lastErrorTime     time.Time
	isThrottled       bool

	// CAPTCHA detection patterns
	captchaPatterns []string

	// WAF block patterns
	wafPatterns []string
}

// NewAdaptiveBackoff creates a backoff strategy starting with baseDelayMs.
func NewAdaptiveBackoff(baseDelayMs int, maxDelayMs int) *AdaptiveBackoff {
	ab := &AdaptiveBackoff{
		baseDelayMs:    baseDelayMs,
		maxDelayMs:     maxDelayMs,
		currentDelayMs: baseDelayMs,
		captchaPatterns: []string{
			"captcha",
			"recaptcha",
			"hcaptcha",
			"challenge",
			"verify_bot",
			"please_verify",
			"robot_check",
		},
		wafPatterns: []string{
			"403 forbidden",
			"429 too many requests",
			"503 service unavailable",
			"cloudflare",
			"akamai",
			"waf",
			"blocked",
			"suspicious",
		},
	}
	return ab
}

// ShouldBackoff determines if a request should be backed off based on response analysis.
func (ab *AdaptiveBackoff) ShouldBackoff(resp *http.Response, body []byte) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		ab.isThrottled = true
		ab.consecutiveErrors++
		return true
	}

	if resp.StatusCode == http.StatusServiceUnavailable {
		ab.isThrottled = true
		ab.consecutiveErrors++
		return true
	}

	if resp.StatusCode == http.StatusForbidden {
		// Check if it's a CAPTCHA or WAF block
		if ab.isCaptchaOrWafBlock(resp, body) {
			ab.isThrottled = true
			ab.consecutiveErrors++
			return true
		}
	}

	return false
}

// isCaptchaOrWafBlock detects CAPTCHA challenges or WAF blocks in response.
func (ab *AdaptiveBackoff) isCaptchaOrWafBlock(resp *http.Response, body []byte) bool {
	bodyStr := strings.ToLower(string(body))

	// Check CAPTCHA patterns
	for _, pattern := range ab.captchaPatterns {
		if strings.Contains(bodyStr, pattern) {
			slog.Info("CAPTCHA challenge detected", "pattern", pattern)
			return true
		}
	}

	// Check WAF patterns
	for _, pattern := range ab.wafPatterns {
		if strings.Contains(bodyStr, pattern) {
			slog.Info("WAF block detected", "pattern", pattern)
			return true
		}
	}

	// Check response headers for WAF signatures
	if resp.Header.Get("Server") != "" {
		server := strings.ToLower(resp.Header.Get("Server"))
		if strings.Contains(server, "cloudflare") || strings.Contains(server, "akamai") {
			return true
		}
	}

	return false
}

// CalculateDelay calculates the next backoff delay with exponential backoff + jitter.
func (ab *AdaptiveBackoff) CalculateDelay() time.Duration {
	// Exponential backoff: delay = base * (2 ^ errors) + random jitter
	exponentialComponent := int(math.Pow(2.0, float64(ab.consecutiveErrors)))
	delayMs := ab.baseDelayMs * exponentialComponent

	// Cap at max delay
	if delayMs > ab.maxDelayMs {
		delayMs = ab.maxDelayMs
	}

	// Add random jitter (up to 25% of delay)
	jitter := rand.Intn(delayMs / 4)
	totalDelayMs := delayMs + jitter

	ab.currentDelayMs = totalDelayMs
	ab.lastErrorTime = time.Now()

	slog.Info("Adaptive backoff calculated",
		"errors", ab.consecutiveErrors,
		"delayMs", totalDelayMs,
		"isThrottled", ab.isThrottled)

	return time.Duration(totalDelayMs) * time.Millisecond
}

// WaitAndRetry applies backoff delay and optionally switches proxy/browser.
func (ab *AdaptiveBackoff) WaitAndRetry(ctx context.Context, cb func() error) error {
	delay := ab.CalculateDelay()
	slog.Info("Backing off request", "delayMs", delay.Milliseconds())

	select {
	case <-time.After(delay):
		// Retry
		if err := cb(); err != nil {
			ab.consecutiveErrors++
			return fmt.Errorf("retry failed after backoff: %w", err)
		}
		ab.Reset() // Reset on success
		return nil

	case <-ctx.Done():
		return fmt.Errorf("backoff cancelled: %w", ctx.Err())
	}
}

// Reset resets the backoff state on successful request.
func (ab *AdaptiveBackoff) Reset() {
	ab.consecutiveErrors = 0
	ab.currentDelayMs = ab.baseDelayMs
	ab.isThrottled = false
	slog.Debug("Backoff state reset on successful request")
}

// IsThrottled returns true if currently throttled/rate-limited.
func (ab *AdaptiveBackoff) IsThrottled() bool {
	return ab.isThrottled
}

// GetCurrentDelay returns the current calculated delay.
func (ab *AdaptiveBackoff) GetCurrentDelay() time.Duration {
	return time.Duration(ab.currentDelayMs) * time.Millisecond
}

// AddCAPTCHAPattern adds a custom CAPTCHA detection pattern.
func (ab *AdaptiveBackoff) AddCAPTCHAPattern(pattern string) {
	ab.captchaPatterns = append(ab.captchaPatterns, strings.ToLower(pattern))
}

// AddWAFPattern adds a custom WAF block detection pattern.
func (ab *AdaptiveBackoff) AddWAFPattern(pattern string) {
	ab.wafPatterns = append(ab.wafPatterns, strings.ToLower(pattern))
}

// RateLimiter wraps HTTP requests with adaptive backoff.
type RateLimiter struct {
	backoff *AdaptiveBackoff
	client  *http.Client
}

// NewRateLimiter creates a rate limiter with adaptive backoff.
func NewRateLimiter(client *http.Client, baseDelayMs int, maxDelayMs int) *RateLimiter {
	return &RateLimiter{
		backoff: NewAdaptiveBackoff(baseDelayMs, maxDelayMs),
		client:  client,
	}
}

// Do executes an HTTP request with automatic backoff on throttling.
func (rl *RateLimiter) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		resp, err := rl.client.Do(req)
		if err != nil {
			if attempt < maxRetries-1 {
				continue
			}
			return nil, err
		}

		// Read response body for pattern matching
		var body []byte
		if resp.Body != nil {
			var err error
			body, err = io.ReadAll(resp.Body)
			resp.Body = io.NopCloser(bytes.NewReader(body))
			if err != nil {
				return resp, nil
			}
		}

		// Check if backoff is needed
		if !rl.backoff.ShouldBackoff(resp, body) {
			rl.backoff.Reset()
			return resp, nil
		}

		// Close current response
		resp.Body.Close()

		// Apply backoff if not last attempt
		if attempt < maxRetries-1 {
			delay := rl.backoff.CalculateDelay()
			select {
			case <-time.After(delay):
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	return nil, fmt.Errorf("max retries exceeded after %d attempts", maxRetries)
}

// GetStats returns current backoff statistics.
func (rl *RateLimiter) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"consecutive_errors": rl.backoff.consecutiveErrors,
		"current_delay_ms":   rl.backoff.currentDelayMs,
		"is_throttled":       rl.backoff.isThrottled,
		"last_error_time":    rl.backoff.lastErrorTime,
	}
}

// TokenBucket implements token bucket rate limiting per target.
type TokenBucket struct {
	capacity   int64
	tokens     int64
	refillRate int64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewTokenBucket creates a new token bucket with capacity and refill rate (tokens per second).
func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request is allowed based on available tokens.
func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	// Refill tokens
	tokensToAdd := int64(elapsed * float64(tb.refillRate))
	tb.tokens += tokensToAdd
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now

	// Check if we have enough tokens
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}

	return false
}

// GetAvailableTokens returns the current number of available tokens.
func (tb *TokenBucket) GetAvailableTokens() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens
}

// PerTargetRateLimiter manages rate limiting per target/domain.
type PerTargetRateLimiter struct {
	buckets      map[string]*TokenBucket
	defaultLimit int64
	defaultRate  int64
	mu           sync.RWMutex
}

// NewPerTargetRateLimiter creates a per-target rate limiter.
func NewPerTargetRateLimiter(defaultLimit, defaultRate int64) *PerTargetRateLimiter {
	return &PerTargetRateLimiter{
		buckets:      make(map[string]*TokenBucket),
		defaultLimit: defaultLimit,
		defaultRate:  defaultRate,
	}
}

// Allow checks if a request to the target is allowed.
func (pt *PerTargetRateLimiter) Allow(target string) bool {
	pt.mu.RLock()
	bucket, exists := pt.buckets[target]
	pt.mu.RUnlock()

	if !exists {
		pt.mu.Lock()
		bucket = NewTokenBucket(pt.defaultLimit, pt.defaultRate)
		pt.buckets[target] = bucket
		pt.mu.Unlock()
	}

	return bucket.Allow()
}

// SetCustomLimit sets a custom rate limit for a specific target.
func (pt *PerTargetRateLimiter) SetCustomLimit(target string, limit, rate int64) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.buckets[target] = NewTokenBucket(limit, rate)
}

// GetTargetStats returns statistics for a specific target.
func (pt *PerTargetRateLimiter) GetTargetStats(target string) map[string]interface{} {
	pt.mu.RLock()
	defer pt.mu.RUnlock()

	bucket, exists := pt.buckets[target]
	if !exists {
		return map[string]interface{}{
			"exists": false,
		}
	}

	return map[string]interface{}{
		"exists":           true,
		"available_tokens": bucket.GetAvailableTokens(),
		"capacity":         bucket.capacity,
		"refill_rate":      bucket.refillRate,
	}
}

// WAFDetector provides advanced WAF detection capabilities.
type WAFDetector struct {
	signatures []WAFSignature
}

// WAFSignature represents a WAF detection signature.
type WAFSignature struct {
	Name        string
	Headers     map[string]string
	BodyPattern string
	StatusCode  int
}

// NewWAFDetector creates a new WAF detector with common signatures.
func NewWAFDetector() *WAFDetector {
	return &WAFDetector{
		signatures: []WAFSignature{
			{
				Name: "Cloudflare",
				Headers: map[string]string{
					"Server": "cloudflare",
				},
				BodyPattern: "cf_chl_opt",
				StatusCode:  403,
			},
			{
				Name: "Akamai",
				Headers: map[string]string{
					"Server": "AkamaiGHost",
				},
				StatusCode: 403,
			},
			{
				Name: "AWS WAF",
				Headers: map[string]string{
					"X-Amzn-Request-Id": "",
				},
				StatusCode: 403,
			},
			{
				Name: "ModSecurity",
				Headers: map[string]string{
					"Server": "nginx",
				},
				BodyPattern: "mod_security",
				StatusCode:  403,
			},
		},
	}
}

// DetectWAF analyzes a response to detect WAF blocking.
func (wd *WAFDetector) DetectWAF(resp *http.Response, body []byte) *WAFSignature {
	bodyStr := strings.ToLower(string(body))

	for _, sig := range wd.signatures {
		// Check status code
		if sig.StatusCode != 0 && resp.StatusCode != sig.StatusCode {
			continue
		}

		// Check headers
		headerMatch := true
		for key, value := range sig.Headers {
			headerValue := resp.Header.Get(key)
			if value == "" {
				if headerValue == "" {
					continue
				}
				headerMatch = false
				break
			}
			if !strings.Contains(strings.ToLower(headerValue), strings.ToLower(value)) {
				headerMatch = false
				break
			}
		}

		if !headerMatch {
			continue
		}

		// Check body pattern
		if sig.BodyPattern != "" && !strings.Contains(bodyStr, strings.ToLower(sig.BodyPattern)) {
			continue
		}

		slog.Info("WAF detected", "name", sig.Name, "status", resp.StatusCode)
		return &sig
	}

	return nil
}

// AddSignature adds a custom WAF detection signature.
func (wd *WAFDetector) AddSignature(sig WAFSignature) {
	wd.signatures = append(wd.signatures, sig)
}

// --- Human-like timing utilities ---

// HumanTimer produces inter-request delays that mimic human behavior.
// Uses lognormal distribution (μ=1.5s mean, σ=0.4s std) + occasional long pauses.
type HumanTimer struct {
	baseMu     time.Duration // minimum delay
	baseSigma  time.Duration // standard deviation
	pauseProb  float64       // probability of a long pause (0.05 = 5%)
	pauseDur   time.Duration // long pause duration
	rng        *rand.Rand
}

// NewHumanTimer creates a timer with realistic human pacing.
func NewHumanTimer() *HumanTimer {
	return &HumanTimer{
		baseMu:    1500 * time.Millisecond,
		baseSigma: 400 * time.Millisecond,
		pauseProb:  0.05,
		pauseDur:   12 * time.Second,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// Sleep picks a delay from lognormal distribution, then sleeps.
func (ht *HumanTimer) Sleep() {
	// Lognormal: if X ~ Normal(μ, σ), then exp(X) is lognormal.
	// Mean = exp(μ + σ²/2). For desired mean ≈ baseMu, solve μ.
	// For simplicity: use normal distribution with positive support clamp.
	delay := time.Duration(math.Abs(ht.rng.NormFloat64()*float64(ht.baseSigma) + float64(ht.baseMu)))

	// Occasionally insert a longer pause (reading, thinking)
	if ht.rng.Float64() < ht.pauseProb {
		delay += ht.pauseDur
	}

	time.Sleep(delay)
}

// SleepWithJitter adds a fixed jitter to an expected delay.
func SleepWithJitter(base time.Duration, jitter time.Duration) {
	if jitter <= 0 {
		time.Sleep(base)
		return
	}
	offset := time.Duration(rand.Int63n(int64(jitter)))
	time.Sleep(base + offset)
}

// ExponentialBackoffJitter computes backoff: base * 2^attempt + random(0, base/2).
func BackoffWithJitter(base time.Duration, attempt int) time.Duration {
	if attempt <= 0 {
		return base
	}
	backoff := base * time.Duration(1<<attempt) // exponential
	jitter := time.Duration(rand.Int63n(int64(base) / 2))
	return backoff + jitter
}
