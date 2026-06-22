package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/domain/security"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

type Tool interface {
	Name() string
	Run(ctx context.Context, targets []string, threads int) ([]Event, error)
}

type Event struct {
	Target     string            `json:"target"`
	Source     string            `json:"source"`
	Type       string            `json:"type"`
	Properties map[string]string `json:"properties"`
}

func NewEvent(target, source, eventType string, properties map[string]string) Event {
	if properties == nil {
		properties = make(map[string]string)
	}
	return Event{Target: target, Source: source, Type: eventType, Properties: properties}
}

func NewEventWithSeverity(target, source, eventType string, properties map[string]string, severity string) Event {
	if properties == nil {
		properties = make(map[string]string)
	}
	if severity != "" {
		properties["severity"] = severity
	}
	return NewEvent(target, source, eventType, properties)
}

func ParseOutputLines(output []byte) []string {
	lines := strings.Split(string(output), "\n")
	unique := make([]string, 0, len(lines))
	seen := map[string]struct{}{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		unique = append(unique, line)
	}
	return unique
}

func RunCommandLines(ctx context.Context, name string, args ...string) ([]string, error) {
	return RunCommandStream(ctx, name, args...)
}

func RunCommandWithInputLines(ctx context.Context, stdin []byte, name string, args ...string) ([]string, error) {
	return RunCommandStreamWithInput(ctx, stdin, name, args...)
}

// NewEventsFromLines converts a list of targets (one per line) into a slice of
// Event records with the specified source and shared metadata.
func NewEventsFromLines(lines []string, source string, metadata map[string]string) []Event {
	return NewEventsFromLinesFunc(lines, source, func(line string) map[string]string {
		if len(metadata) == 0 {
			return nil
		}
		copy := make(map[string]string, len(metadata))
		for k, v := range metadata {
			copy[k] = v
		}
		return copy
	})
}

// NewEventsFromLinesFunc converts a list of targets into a slice of Event records,
// using a generator function to produce properties for each line.
func NewEventsFromLinesFunc(lines []string, source string, metadataFunc func(string) map[string]string) []Event {
	if metadataFunc == nil {
		metadataFunc = func(string) map[string]string { return nil }
	}

	// Pre-allocate with initial capacity to reduce allocations
	events := make([]Event, 0, len(lines))

	// Ensure we don't process duplicate events internally
	seen := make(map[string]struct{}, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip ASCII art / banners (heuristic: high density of box-drawing or art characters)
		if !strings.Contains(line, "://") {
			if strings.Count(line, "/")+strings.Count(line, "_")+strings.Count(line, "\\")+strings.Count(line, "|") > 5 {
				continue
			}
		}

		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}

		properties := metadataFunc(line)
		events = append(events, NewEvent(line, source, "discovery", properties))
	}
	return events
}

type contextKey int

const (
	_ contextKey = iota
	apiKeyContextKey
	wordlistDirContextKey
	tmpResultsDirKey
	proxiesContextKey
	rateLimitContextKey
	toolRateLimitsKey
	lowResourceContextKey
	scanModeContextKey
	headersContextKey
	autoUpdateContextKey
	portsContextKey
	containerModeContextKey
	dockerImagesContextKey
	quotaGuardContextKey
	insecureContextKey
	dryRunContextKey
)

func WithAPIKeys(ctx context.Context, keys map[string]string) context.Context {
	return context.WithValue(ctx, apiKeyContextKey, keys)
}

func GetAPIKey(ctx context.Context, provider string) string {
	if keys, ok := ctx.Value(apiKeyContextKey).(map[string]string); ok {
		return keys[provider]
	}
	return ""
}

func WithWordlistsDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, wordlistDirContextKey, dir)
}

func WithTmpResultsDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, tmpResultsDirKey, dir)
}

func GetTmpResultsDir(ctx context.Context) string {
	if dir, ok := ctx.Value(tmpResultsDirKey).(string); ok {
		return dir
	}
	return ""
}

func wordlistsDirFromContext(ctx context.Context) string {
	if dir, ok := ctx.Value(wordlistDirContextKey).(string); ok {
		return dir
	}
	return ""
}

func GetWordlistPath(ctx context.Context, name string) string {
	dir := wordlistsDirFromContext(ctx)
	if dir == "" {
		return ""
	}
	// Mapping for common wordlist types
	mapping := map[string]string{
		"dns":       "dns-5k.txt",
		"directory": "raft-small-files.txt",
		"subdomain": "subdomains-top1million-5000.txt",
		"api":       "api-endpoints.txt",
	}
	if filename, ok := mapping[name]; ok {
		return filepath.Join(dir, filename)
	}
	// Fallback to seclists_common.txt for unknown types
	return filepath.Join(dir, "seclists_common.txt")
}

func WithProxies(ctx context.Context, proxies []string) context.Context {
	return context.WithValue(ctx, proxiesContextKey, proxies)
}

func GetProxies(ctx context.Context) []string {
	if proxies, ok := ctx.Value(proxiesContextKey).([]string); ok {
		return proxies
	}
	return nil
}

func WithRateLimit(ctx context.Context, limit int) context.Context {
	return context.WithValue(ctx, rateLimitContextKey, limit)
}

func RateLimitFromCtx(ctx context.Context) int {
	if limit, ok := ctx.Value(rateLimitContextKey).(int); ok {
		return limit
	}
	return 0
}

func WithToolRateLimits(ctx context.Context, limits map[string]int) context.Context {
	return context.WithValue(ctx, toolRateLimitsKey, limits)
}

func ToolRateLimitFromCtx(ctx context.Context, toolName string) int {
	limit := ConfiguredToolRateLimitFromCtx(ctx, toolName)
	return GetDynamicRateLimit(toolName, limit)
}

func ConfiguredToolRateLimitFromCtx(ctx context.Context, toolName string) int {
	limit := 0
	if limits, ok := ctx.Value(toolRateLimitsKey).(map[string]int); ok {
		if l, found := limits[toolName]; found && l > 0 {
			limit = l
		}
	}
	if limit == 0 {
		limit = RateLimitFromCtx(ctx)
	}
	return limit
}

func WithLowResource(ctx context.Context, low bool) context.Context {
	return context.WithValue(ctx, lowResourceContextKey, low)
}

func LowResourceFromCtx(ctx context.Context) bool {
	if low, ok := ctx.Value(lowResourceContextKey).(bool); ok {
		return low
	}
	return false
}

func WithScanMode(ctx context.Context, mode string) context.Context {
	return context.WithValue(ctx, scanModeContextKey, mode)
}

func GetScanMode(ctx context.Context) string {
	if mode, ok := ctx.Value(scanModeContextKey).(string); ok {
		return mode
	}
	return "normal"
}

func WithHeaders(ctx context.Context, headers map[string]string) context.Context {
	return context.WithValue(ctx, headersContextKey, headers)
}

func HeadersFromCtx(ctx context.Context) map[string]string {
	if headers, ok := ctx.Value(headersContextKey).(map[string]string); ok {
		return headers
	}
	return nil
}

func WithAutoUpdate(ctx context.Context, update bool) context.Context {
	return context.WithValue(ctx, autoUpdateContextKey, update)
}

func AutoUpdateFromCtx(ctx context.Context) bool {
	if update, ok := ctx.Value(autoUpdateContextKey).(bool); ok {
		return update
	}
	return false
}

func WithPorts(ctx context.Context, ports string) context.Context {
	return context.WithValue(ctx, portsContextKey, ports)
}

func PortsFromCtx(ctx context.Context) string {
	if ports, ok := ctx.Value(portsContextKey).(string); ok {
		return ports
	}
	return ""
}

func WithContainerMode(ctx context.Context, mode bool) context.Context {
	return context.WithValue(ctx, containerModeContextKey, mode)
}

func ContainerModeFromCtx(ctx context.Context) bool {
	if mode, ok := ctx.Value(containerModeContextKey).(bool); ok {
		return mode
	}
	return false
}

func WithDockerImages(ctx context.Context, images map[string]string) context.Context {
	return context.WithValue(ctx, dockerImagesContextKey, images)
}

func DockerImagesFromCtx(ctx context.Context) map[string]string {
	if images, ok := ctx.Value(dockerImagesContextKey).(map[string]string); ok {
		return images
	}
	return nil
}

func WithQuotaGuard(ctx context.Context, qg *utils.QuotaGuard) context.Context {
	return context.WithValue(ctx, quotaGuardContextKey, qg)
}

func GetQuotaGuard(ctx context.Context) *utils.QuotaGuard {
	if qg, ok := ctx.Value(quotaGuardContextKey).(*utils.QuotaGuard); ok {
		return qg
	}
	return nil
}

func WithInsecure(ctx context.Context, insecure bool) context.Context {
	return context.WithValue(ctx, insecureContextKey, insecure)
}

func InsecureFromCtx(ctx context.Context) bool {
	val := ctx.Value(insecureContextKey)
	if val == nil {
		return false // Default to false if not set
	}
	if insecure, ok := val.(bool); ok {
		return insecure
	}
	return false
}



func WithDryRun(ctx context.Context, dryRun bool) context.Context {
	return context.WithValue(ctx, dryRunContextKey, dryRun)
}

func DryRunFromCtx(ctx context.Context) bool {
	if dryRun, ok := ctx.Value(dryRunContextKey).(bool); ok {
		return dryRun
	}
	return false
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
