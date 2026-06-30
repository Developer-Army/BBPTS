package recon

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/shared/quota"
)

type ScanContext struct {
	Ports            string
	ContainerMode    bool
	DockerImages     map[string]string
	QuotaGuard       *quota.QuotaGuard
	Insecure         bool
	DryRun           bool
	InteractshOOBURL string
	WAFContext       string
	ForceHTTP1       bool
	LowResource      bool
	APIKeys          map[string]string
	Headers          map[string]string
	ExploitSQLI      bool
	AuthSessions     []AuthSession
}

type AuthSession struct {
	Label   string            `json:"label"`
	Headers map[string]string `json:"headers"`
}

type Tool interface {
	Name() string
	Run(ctx context.Context, scanCtx *ScanContext, targets []string, threads int) ([]Event, error)
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
	interactshOOBURLKey
	wafContextKey
	forceHTTP1ContextKey
	exploitSQLIContextKey
	authSessionsContextKey
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

func APIKeysFromCtx(ctx context.Context) map[string]string {
	if keys, ok := ctx.Value(apiKeyContextKey).(map[string]string); ok {
		return keys
	}
	return nil
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

func WordlistsDirFromContext(ctx context.Context) string {
	if dir, ok := ctx.Value(wordlistDirContextKey).(string); ok {
		return dir
	}
	return ""
}

func GetWordlistPath(ctx context.Context, name string) string {
	dir := WordlistsDirFromContext(ctx)
	if dir == "" {
		return ""
	}
	mapping := map[string]string{
		"dns":       "dns-5k.txt",
		"directory": "raft-small-files.txt",
		"subdomain": "subdomains-top1million-5000.txt",
		"api":       "api-endpoints.txt",
	}
	if filename, ok := mapping[name]; ok {
		return filepath.Join(dir, filename)
	}
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

func WithQuotaGuard(ctx context.Context, qg *quota.QuotaGuard) context.Context {
	return context.WithValue(ctx, quotaGuardContextKey, qg)
}

func GetQuotaGuard(ctx context.Context) *quota.QuotaGuard {
	if qg, ok := ctx.Value(quotaGuardContextKey).(*quota.QuotaGuard); ok {
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
		return false
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

func WithInteractshOOBURL(ctx context.Context, url string) context.Context {
	return context.WithValue(ctx, interactshOOBURLKey, url)
}

func InteractshOOBURLFromCtx(ctx context.Context) string {
	if url, ok := ctx.Value(interactshOOBURLKey).(string); ok {
		return url
	}
	return ""
}

func WithWAFContext(ctx context.Context, waf string) context.Context {
	return context.WithValue(ctx, wafContextKey, waf)
}

func WAFContextFromCtx(ctx context.Context) string {
	if waf, ok := ctx.Value(wafContextKey).(string); ok {
		return waf
	}
	return ""
}

func WithForceHTTP1(ctx context.Context, force bool) context.Context {
	return context.WithValue(ctx, forceHTTP1ContextKey, force)
}

func ForceHTTP1FromCtx(ctx context.Context) bool {
	if force, ok := ctx.Value(forceHTTP1ContextKey).(bool); ok {
		return force
	}
	return false
}

func WithExploitSQLI(ctx context.Context, exploit bool) context.Context {
	return context.WithValue(ctx, exploitSQLIContextKey, exploit)
}

func ExploitSQLIFromCtx(ctx context.Context) bool {
	if exploit, ok := ctx.Value(exploitSQLIContextKey).(bool); ok {
		return exploit
	}
	return false
}

func WithAuthSessions(ctx context.Context, sessions []AuthSession) context.Context {
	return context.WithValue(ctx, authSessionsContextKey, sessions)
}

func AuthSessionsFromCtx(ctx context.Context) []AuthSession {
	if sessions, ok := ctx.Value(authSessionsContextKey).([]AuthSession); ok {
		return sessions
	}
	return nil
}
