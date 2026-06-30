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

type AdaptiveBackoff struct {
	mu                sync.RWMutex
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

func (ab *AdaptiveBackoff) ShouldBackoff(resp *http.Response, body []byte) bool {
	ab.mu.Lock()
	defer ab.mu.Unlock()
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

		if ab.isCaptchaOrWafBlock(resp, body) {
			ab.isThrottled = true
			ab.consecutiveErrors++
			return true
		}
	}

	return false
}

func (ab *AdaptiveBackoff) isCaptchaOrWafBlock(resp *http.Response, body []byte) bool {
	bodyStr := strings.ToLower(string(body))

	for _, pattern := range ab.captchaPatterns {
		if strings.Contains(bodyStr, pattern) {
			slog.Info("CAPTCHA challenge detected", "pattern", pattern)
			return true
		}
	}

	for _, pattern := range ab.wafPatterns {
		if strings.Contains(bodyStr, pattern) {
			slog.Info("WAF block detected", "pattern", pattern)
			return true
		}
	}

	if resp.Header.Get("Server") != "" {
		server := strings.ToLower(resp.Header.Get("Server"))
		if strings.Contains(server, "cloudflare") || strings.Contains(server, "akamai") {
			return true
		}
	}

	return false
}

func (ab *AdaptiveBackoff) CalculateDelay() time.Duration {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	exponentialComponent := int(math.Pow(2.0, float64(ab.consecutiveErrors)))
	delayMs := ab.baseDelayMs * exponentialComponent

	if delayMs > ab.maxDelayMs {
		delayMs = ab.maxDelayMs
	}

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

func (ab *AdaptiveBackoff) WaitAndRetry(ctx context.Context, cb func() error) error {
	delay := ab.CalculateDelay()
	slog.Info("Backing off request", "delayMs", delay.Milliseconds())

	select {
	case <-time.After(delay):

		if err := cb(); err != nil {
			ab.mu.Lock()
			ab.consecutiveErrors++
			ab.mu.Unlock()
			return fmt.Errorf("retry failed after backoff: %w", err)
		}
		ab.Reset()
		return nil

	case <-ctx.Done():
		return fmt.Errorf("backoff cancelled: %w", ctx.Err())
	}
}

func (ab *AdaptiveBackoff) Reset() {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.consecutiveErrors = 0
	ab.currentDelayMs = ab.baseDelayMs
	ab.isThrottled = false
	slog.Debug("Backoff state reset on successful request")
}

func (ab *AdaptiveBackoff) IsThrottled() bool {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return ab.isThrottled
}

func (ab *AdaptiveBackoff) GetCurrentDelay() time.Duration {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	return time.Duration(ab.currentDelayMs) * time.Millisecond
}

func (ab *AdaptiveBackoff) AddCAPTCHAPattern(pattern string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.captchaPatterns = append(ab.captchaPatterns, strings.ToLower(pattern))
}

func (ab *AdaptiveBackoff) AddWAFPattern(pattern string) {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.wafPatterns = append(ab.wafPatterns, strings.ToLower(pattern))
}

func (ab *AdaptiveBackoff) IsBlockDetected(text string) bool {
	ab.mu.RLock()
	defer ab.mu.RUnlock()
	lower := strings.ToLower(text)
	for _, pattern := range ab.captchaPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	for _, pattern := range ab.wafPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

func (ab *AdaptiveBackoff) RecordBlock() {
	ab.mu.Lock()
	defer ab.mu.Unlock()
	ab.isThrottled = true
	ab.consecutiveErrors++
}

type RateLimiter struct {
	backoff *AdaptiveBackoff
	client  *http.Client
}

func NewRateLimiter(client *http.Client, baseDelayMs int, maxDelayMs int) *RateLimiter {
	return &RateLimiter{
		backoff: NewAdaptiveBackoff(baseDelayMs, maxDelayMs),
		client:  client,
	}
}

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
			body, err = io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
			resp.Body = io.NopCloser(bytes.NewReader(body))
			if err != nil {
				return resp, nil
			}
		}

		if !rl.backoff.ShouldBackoff(resp, body) {
			rl.backoff.Reset()
			return resp, nil
		}

		resp.Body.Close()

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

func (rl *RateLimiter) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"consecutive_errors": rl.backoff.consecutiveErrors,
		"current_delay_ms":   rl.backoff.currentDelayMs,
		"is_throttled":       rl.backoff.isThrottled,
		"last_error_time":    rl.backoff.lastErrorTime,
	}
}

type TokenBucket struct {
	capacity   int64
	tokens     int64
	refillRate int64
	lastRefill time.Time
	mu         sync.Mutex
}

func NewTokenBucket(capacity, refillRate int64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

func (tb *TokenBucket) Allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	tokensToAdd := int64(elapsed * float64(tb.refillRate))
	tb.tokens += tokensToAdd
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}

	return false
}

func (tb *TokenBucket) GetAvailableTokens() int64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return tb.tokens
}

type PerTargetRateLimiter struct {
	buckets      map[string]*TokenBucket
	defaultLimit int64
	defaultRate  int64
	mu           sync.RWMutex
}

func NewPerTargetRateLimiter(defaultLimit, defaultRate int64) *PerTargetRateLimiter {
	return &PerTargetRateLimiter{
		buckets:      make(map[string]*TokenBucket),
		defaultLimit: defaultLimit,
		defaultRate:  defaultRate,
	}
}

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

func (pt *PerTargetRateLimiter) SetCustomLimit(target string, limit, rate int64) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.buckets[target] = NewTokenBucket(limit, rate)
}

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

type WAFDetector struct {
	signatures []WAFSignature
}

type WAFSignature struct {
	Name        string
	Headers     map[string]string
	BodyPattern string
	StatusCode  int
}

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

func (wd *WAFDetector) DetectWAF(resp *http.Response, body []byte) *WAFSignature {
	bodyStr := strings.ToLower(string(body))

	for _, sig := range wd.signatures {

		if sig.StatusCode != 0 && resp.StatusCode != sig.StatusCode {
			continue
		}

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

		if sig.BodyPattern != "" && !strings.Contains(bodyStr, strings.ToLower(sig.BodyPattern)) {
			continue
		}

		slog.Info("WAF detected", "name", sig.Name, "status", resp.StatusCode)
		return &sig
	}

	return nil
}

func (wd *WAFDetector) AddSignature(sig WAFSignature) {
	wd.signatures = append(wd.signatures, sig)
}

type HumanTimer struct {
	baseMu    time.Duration // minimum delay
	baseSigma time.Duration // standard deviation
	pauseProb float64       // probability of a long pause (0.05 = 5%)
	pauseDur  time.Duration // long pause duration
	rng       *rand.Rand
	mu        sync.Mutex
}

func NewHumanTimer() *HumanTimer {
	return &HumanTimer{
		baseMu:    1500 * time.Millisecond,
		baseSigma: 400 * time.Millisecond,
		pauseProb: 0.05,
		pauseDur:  12 * time.Second,
		rng:       rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (ht *HumanTimer) Sleep() {

	ht.mu.Lock()
	normVal := ht.rng.NormFloat64()
	isPause := ht.rng.Float64() < ht.pauseProb
	ht.mu.Unlock()

	delay := time.Duration(math.Abs(normVal*float64(ht.baseSigma) + float64(ht.baseMu)))

	if isPause {
		delay += ht.pauseDur
	}

	time.Sleep(delay)
}

func SleepWithJitter(base time.Duration, jitter time.Duration) {
	if jitter <= 0 {
		time.Sleep(base)
		return
	}
	offset := time.Duration(rand.Int63n(int64(jitter)))
	time.Sleep(base + offset)
}

func BackoffWithJitter(base time.Duration, attempt int) time.Duration {
	if attempt <= 0 {
		return base
	}
	backoff := base * time.Duration(1<<attempt)
	jitter := time.Duration(rand.Int63n(int64(base) / 2))
	return backoff + jitter
}

type PerHostAdaptiveLimiter struct {
	limiters    map[string]*AdaptiveBackoff
	baseDelayMs int
	maxDelayMs  int
	mu          sync.RWMutex
}

func NewPerHostAdaptiveLimiter(baseDelayMs, maxDelayMs int) *PerHostAdaptiveLimiter {
	return &PerHostAdaptiveLimiter{
		limiters:    make(map[string]*AdaptiveBackoff),
		baseDelayMs: baseDelayMs,
		maxDelayMs:  maxDelayMs,
	}
}

func (phal *PerHostAdaptiveLimiter) GetBackoff(host string) *AdaptiveBackoff {
	phal.mu.RLock()
	ab, exists := phal.limiters[host]
	phal.mu.RUnlock()

	if !exists {
		phal.mu.Lock()
		ab = NewAdaptiveBackoff(phal.baseDelayMs, phal.maxDelayMs)
		phal.limiters[host] = ab
		phal.mu.Unlock()
	}
	return ab
}
