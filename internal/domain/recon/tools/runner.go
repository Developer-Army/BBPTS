package tools

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/domain/security"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
)

var (
	toolBackoffs        = make(map[string]*network.AdaptiveBackoff)
	toolBackoffsMu      sync.RWMutex
	dynamicRateLimits   = make(map[string]int)
	dynamicRateLimitsMu sync.RWMutex
)

func getToolBackoff(toolName string) *network.AdaptiveBackoff {
	toolBackoffsMu.Lock()
	defer toolBackoffsMu.Unlock()
	ab, exists := toolBackoffs[toolName]
	if !exists {
		ab = network.NewAdaptiveBackoff(1000, 30000)
		toolBackoffs[toolName] = ab
	}
	return ab
}

func GetDynamicRateLimit(toolName string, baseLimit int) int {
	dynamicRateLimitsMu.RLock()
	limit, exists := dynamicRateLimits[toolName]
	dynamicRateLimitsMu.RUnlock()
	if exists {
		return limit
	}
	return baseLimit
}

func SetDynamicRateLimit(toolName string, limit int) {
	dynamicRateLimitsMu.Lock()
	dynamicRateLimits[toolName] = limit
	dynamicRateLimitsMu.Unlock()
}

func ThrottleToolRateLimit(toolName string, baseLimit int) {
	current := GetDynamicRateLimit(toolName, baseLimit)
	if current <= 0 {
		return
	}
	newLimit := current / 2
	if newLimit < 1 {
		newLimit = 1
	}
	SetDynamicRateLimit(toolName, newLimit)
	slog.Warn("Throttled rate limit due to WAF/rate-limit detection", "tool", toolName, "old_limit", current, "new_limit", newLimit)
}

func RecoverToolRateLimit(toolName string, baseLimit int) {
	current := GetDynamicRateLimit(toolName, baseLimit)
	if current < baseLimit {
		increase := (baseLimit - current) / 5
		if increase < 1 {
			increase = 1
		}
		newLimit := current + increase
		if newLimit > baseLimit {
			newLimit = baseLimit
		}
		SetDynamicRateLimit(toolName, newLimit)
		slog.Info("Recovered rate limit", "tool", toolName, "old_limit", current, "new_limit", newLimit)
	}
}

// RunCommandStream runs an external command and reads stdout stream line-by-line, returning unique lines.
func RunCommandStream(ctx context.Context, name string, args ...string) ([]string, error) {
	return RunCommandStreamWithInput(ctx, nil, name, args...)
}

// RunCommandStreamWithInput runs an external command with stdin provided, and reads stdout stream line-by-line, returning unique lines.
func RunCommandStreamWithInput(ctx context.Context, stdin []byte, name string, args ...string) ([]string, error) {
	if recon.DryRunFromCtx(ctx) {
		fmt.Printf("[Dry-Run] Would execute: %s %s\n", name, strings.Join(args, " "))
		var mockLines []string
		switch name {
		case "subfinder", "amass", "assetfinder", "crtsh":
			var inputTargets []string
			if stdin != nil {
				inputTargets = strings.Split(string(stdin), "\n")
			} else {
				inputTargets = []string{"target.com"}
			}
			for _, t := range inputTargets {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				mockLines = append(mockLines, "sub1."+t, "sub2."+t)
			}
		case "httpx":
			var inputTargets []string
			if stdin != nil {
				inputTargets = strings.Split(string(stdin), "\n")
			}
			for _, t := range inputTargets {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				mockLines = append(mockLines, fmt.Sprintf(`{"url":"https://%s","statuscode":200,"title":"Mock Title","server":"nginx"}`, t))
			}
		case "katana", "gau", "hakrawler":
			var inputTargets []string
			if stdin != nil {
				inputTargets = strings.Split(string(stdin), "\n")
			} else {
				inputTargets = []string{"https://target.com"}
			}
			for _, t := range inputTargets {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				prefix := strings.TrimSuffix(t, "/")
				if !strings.HasPrefix(prefix, "http") {
					prefix = "https://" + prefix
				}
				mockLines = append(mockLines, prefix+"/api/v1", prefix+"/login")
			}
		case "nuclei":
			var inputTargets []string
			if stdin != nil {
				inputTargets = strings.Split(string(stdin), "\n")
			}
			for _, t := range inputTargets {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				mockLines = append(mockLines, fmt.Sprintf(`{"template-id":"mock-vuln","info":{"severity":"medium"},"matched-at":"%s"}`, t))
			}
		case "dalfox":
			var inputTargets []string
			if stdin != nil {
				inputTargets = strings.Split(string(stdin), "\n")
			}
			for _, t := range inputTargets {
				t = strings.TrimSpace(t)
				if t == "" {
					continue
				}
				mockLines = append(mockLines, fmt.Sprintf(`{"type":"vulnerability","url":"%s","payload":"<script>alert(1)</script>","severity":"medium"}`, t))
			}
		}
		return mockLines, nil
	}

	cmd := PrepareCommand(ctx, name, args...)

	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	unique := make([]string, 0)
	seen := map[string]struct{}{}

	scanner := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	ab := getToolBackoff(name)
	blockDetected := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if !blockDetected && ab.IsBlockDetected(line) {
			blockDetected = true
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		unique = append(unique, line)
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return unique, scanErr
	}

	err = waitForCommand(ctx, cmd, &stderr)
	errStr := strings.TrimSpace(stderr.String())

	if !blockDetected && ab.IsBlockDetected(errStr) {
		blockDetected = true
	}
	if !blockDetected && err != nil {
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "429") || strings.Contains(errLower, "too many requests") {
			blockDetected = true
		}
	}

	baseLimit := recon.ConfiguredToolRateLimitFromCtx(ctx, name)
	if blockDetected {
		ab.RecordBlock()
		ThrottleToolRateLimit(name, baseLimit)
		delay := ab.CalculateDelay()
		slog.Warn("WAF block/rate-limit detected: backing off execution", "tool", name, "delay", delay)
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return unique, ctx.Err()
		}
	} else {
		ab.Reset()
		RecoverToolRateLimit(name, baseLimit)
	}

	if err != nil {
		if errStr != "" {
			slog.Debug("command failed", "tool", name, "error", err, "stderr", errStr)
			return unique, fmt.Errorf("%s failed: %w", name, err)
		}
		slog.Debug("command failed", "tool", name, "error", err)
		return unique, fmt.Errorf("%s failed: %w", name, err)
	}

	return unique, nil
}

func ToolRateLimitFromCtx(ctx context.Context, toolName string) int {
	limit := recon.ConfiguredToolRateLimitFromCtx(ctx, toolName)
	return GetDynamicRateLimit(toolName, limit)
}

// NewSafeHTTPClient returns an http.Client with built-in SSRF protection.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				pinnedAddr, _, err := security.ResolveAndValidateAddr(ctx, addr)
				if err != nil {
					return nil, err
				}
				h, _, err := net.SplitHostPort(pinnedAddr)
				if err == nil {
					if addrVal, err := netip.ParseAddr(h); err == nil && security.IsPrivateAddr(addrVal) {
						return nil, fmt.Errorf("SSRF prevention: private IP blocked: %s", h)
					}
				}
				dialer := &net.Dialer{
					Timeout:   timeout,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, pinnedAddr)
			},
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				MaxVersion: tls.VersionTLS13,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			san := security.NewSanitizer()
			if err := san.ValidateURL(req.URL.String()); err != nil {
				return fmt.Errorf("SSRF validation blocked redirect: %w", err)
			}
			return nil
		},
	}
}

// NewSafeRateLimitedClient returns a client wrapper that has both SSRF protection and Adaptive Backoff.
func NewSafeRateLimitedClient(timeout time.Duration, baseDelayMs, maxDelayMs int) *network.RateLimiter {
	client := NewSafeHTTPClient(timeout)
	return network.NewRateLimiter(client, baseDelayMs, maxDelayMs)
}
