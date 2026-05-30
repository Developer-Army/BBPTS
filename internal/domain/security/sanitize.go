package security

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

var lookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	var resolver net.Resolver
	return resolver.LookupIP(ctx, "ip", host)
}

// Sanitizer provides input validation and sanitization for security.
type Sanitizer struct {
	// Allowed patterns for different input types
	fleetNamePattern *regexp.Regexp
	toolNamePattern  *regexp.Regexp
	filePathPattern  *regexp.Regexp
	urlPattern       *regexp.Regexp
}

// NewSanitizer creates a new sanitizer with security patterns.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{
		// Fleet names: alphanumeric, hyphens, underscores only, max 64 chars
		fleetNamePattern: regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`),
		// Tool names: lowercase alphanumeric, hyphens only (standard tool naming)
		toolNamePattern: regexp.MustCompile(`^[a-z0-9-]{1,32}$`),
		// File paths: prevent directory traversal
		filePathPattern: regexp.MustCompile(`^[a-zA-Z0-9_./-]{1,256}$`),
		// Basic URL pattern for validation
		urlPattern: regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/$.?#].[^\s]*$`),
	}
}

// ValidateFleetName validates a fleet name for security.
func (s *Sanitizer) ValidateFleetName(name string) error {
	if name == "" {
		return fmt.Errorf("fleet name cannot be empty")
	}

	// Check for shell metacharacters
	if containsShellMetacharacters(name) {
		return fmt.Errorf("fleet name contains invalid characters: %s", name)
	}

	// Check against allowed pattern
	if !s.fleetNamePattern.MatchString(name) {
		return fmt.Errorf("fleet name must be alphanumeric with hyphens/underscores only, max 64 chars: %s", name)
	}

	return nil
}

// ValidateToolName validates a tool name for security.
func (s *Sanitizer) ValidateToolName(name string) error {
	if name == "" {
		return fmt.Errorf("tool name cannot be empty")
	}

	// Check for shell metacharacters
	if containsShellMetacharacters(name) {
		return fmt.Errorf("tool name contains invalid characters: %s", name)
	}

	// Check against allowed pattern
	if !s.toolNamePattern.MatchString(name) {
		return fmt.Errorf("tool name must be lowercase alphanumeric with hyphens only, max 32 chars: %s", name)
	}

	return nil
}

// ValidateFilePath validates a file path to prevent directory traversal.
func (s *Sanitizer) ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Check for directory traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("file path contains directory traversal: %s", path)
	}

	// Check for shell metacharacters
	if containsShellMetacharacters(path) {
		return fmt.Errorf("file path contains invalid characters: %s", path)
	}

	// Check against allowed pattern
	if !s.filePathPattern.MatchString(path) {
		return fmt.Errorf("file path contains invalid characters: %s", path)
	}

	return nil
}

// privatePrefixes contains blacklisted internal network segments.
var privatePrefixes []netip.Prefix

func init() {
	cidrs := []string{
		// IPv4 Private/Local
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"0.0.0.0/8",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
		// IPv6 Private/Local
		"::1/128",
		"::/128",
		"fe80::/10",
		"fc00::/7",
		"ff00::/8",
	}
	for _, s := range cidrs {
		prefix, err := netip.ParsePrefix(s)
		if err == nil {
			privatePrefixes = append(privatePrefixes, prefix)
		}
	}
}

// IsPrivateAddr checks if a netip.Addr belongs to private/internal range.
func IsPrivateAddr(addr netip.Addr) bool {
	if os.Getenv("BBPTS_ALLOW_PRIVATE_IPS") == "true" {
		return false
	}
	if !addr.IsValid() {
		return true
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() || addr.IsPrivate() {
		return true
	}
	for _, prefix := range privatePrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// IsPrivateIP checks if an IP belongs to private/internal range.
func IsPrivateIP(ip net.IP) bool {
	if os.Getenv("BBPTS_ALLOW_PRIVATE_IPS") == "true" {
		return false
	}
	if ip == nil {
		return true
	}
	addr, err := netip.ParseAddr(ip.String())
	if err != nil {
		return true
	}
	return IsPrivateAddr(addr)
}

// ParseMixedNotationIP parses decimal, hex, or octal IPv4 notations.
func ParseMixedNotationIP(host string) (net.IP, bool) {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil, false
	}
	if strings.Contains(host, "[") || strings.Contains(host, "]") || strings.Count(host, ":") >= 2 {
		return nil, false
	}

	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, false
	}

	var parsedParts []uint64
	for _, part := range parts {
		if part == "" {
			return nil, false
		}
		var val uint64
		var err error
		partLower := strings.ToLower(part)
		if strings.HasPrefix(partLower, "0x") {
			val, err = strconv.ParseUint(part[2:], 16, 64)
		} else if strings.HasPrefix(part, "0") && len(part) > 1 {
			val, err = strconv.ParseUint(part, 8, 64)
		} else {
			val, err = strconv.ParseUint(part, 10, 64)
		}
		if err != nil {
			return nil, false
		}
		parsedParts = append(parsedParts, val)
	}

	ip := make(net.IP, 4)
	switch len(parsedParts) {
	case 1:
		val := parsedParts[0]
		if val > 0xffffffff {
			return nil, false
		}
		ip[0] = byte(val >> 24)
		ip[1] = byte(val >> 16)
		ip[2] = byte(val >> 8)
		ip[3] = byte(val)
		return ip, true
	case 2:
		a, b := parsedParts[0], parsedParts[1]
		if a > 0xff || b > 0xffffff {
			return nil, false
		}
		ip[0] = byte(a)
		ip[1] = byte(b >> 16)
		ip[2] = byte(b >> 8)
		ip[3] = byte(b)
		return ip, true
	case 3:
		a, b, c := parsedParts[0], parsedParts[1], parsedParts[2]
		if a > 0xff || b > 0xff || c > 0xffff {
			return nil, false
		}
		ip[0] = byte(a)
		ip[1] = byte(b)
		ip[2] = byte(c >> 8)
		ip[3] = byte(c)
		return ip, true
	case 4:
		a, b, c, d := parsedParts[0], parsedParts[1], parsedParts[2], parsedParts[3]
		if a > 0xff || b > 0xff || c > 0xff || d > 0xff {
			return nil, false
		}
		ip[0] = byte(a)
		ip[1] = byte(b)
		ip[2] = byte(c)
		ip[3] = byte(d)
		return ip, true
	}
	return nil, false
}

// ValidateResolvedIPEx pre-resolves a host and checks all its IPs for SSRF protection.
// If strict is true, it fails closed on DNS/resolution failures.
func (s *Sanitizer) ValidateResolvedIPEx(host string, strict bool) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return fmt.Errorf("host cannot be empty")
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	if addr, err := netip.ParseAddr(host); err == nil {
		if IsPrivateAddr(addr) {
			return fmt.Errorf("IP address is private/local: %s", addr.String())
		}
		return nil
	}

	if ip, ok := ParseMixedNotationIP(host); ok {
		if addr, err := netip.ParseAddr(ip.String()); err == nil {
			if IsPrivateAddr(addr) {
				return fmt.Errorf("IP address is private/local: %s", addr.String())
			}
			return nil
		}
		if IsPrivateIP(ip) {
			return fmt.Errorf("IP address is private/local: %s", ip.String())
		}
		return nil
	}

	if ip := net.ParseIP(host); ip != nil {
		if addr, err := netip.ParseAddr(ip.String()); err == nil {
			if IsPrivateAddr(addr) {
				return fmt.Errorf("IP address is private/local: %s", addr.String())
			}
			return nil
		}
		if IsPrivateIP(ip) {
			return fmt.Errorf("IP address is private/local: %s", ip.String())
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	ips, err := lookupIP(ctx, host)
	if err != nil {
		return fmt.Errorf("failed to resolve host %s: %w", host, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses resolved for host %s", host)
	}

	for _, ip := range ips {
		if addr, err := netip.ParseAddr(ip.String()); err == nil {
			if IsPrivateAddr(addr) {
				return fmt.Errorf("host %s resolves to private IP %s", host, addr.String())
			}
		} else {
			if IsPrivateIP(ip) {
				return fmt.Errorf("host %s resolves to private IP %s", host, ip.String())
			}
		}
	}
	return nil
}

// ValidateResolvedIP pre-resolves a host and checks all its IPs for SSRF protection.
func (s *Sanitizer) ValidateResolvedIP(host string) error {
	return s.ValidateResolvedIPEx(host, true)
}

// ValidateResolvedIPStrict pre-resolves a host strictly and fails closed on resolution errors.
func (s *Sanitizer) ValidateResolvedIPStrict(host string) error {
	return s.ValidateResolvedIPEx(host, true)
}

// ValidateURL validates a URL for security.
func (s *Sanitizer) ValidateURL(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Check for shell metacharacters
	if containsShellMetacharactersForURL(urlStr) {
		return fmt.Errorf("URL contains invalid characters: %s", urlStr)
	}

	// Basic URL validation
	if !s.urlPattern.MatchString(urlStr) {
		return fmt.Errorf("invalid URL format: %s", urlStr)
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	host := parsed.Hostname()
	if err := s.ValidateResolvedIP(host); err != nil {
		slog.Warn("SSRF check blocked URL", "url", urlStr, "error", err)
		return fmt.Errorf("URL points to internal address: %s", urlStr)
	}

	return nil
}

// ValidateURLStrict validates a URL strictly for active fetches.
func (s *Sanitizer) ValidateURLStrict(urlStr string) error {
	if urlStr == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Check for shell metacharacters
	if containsShellMetacharactersForURL(urlStr) {
		return fmt.Errorf("URL contains invalid characters: %s", urlStr)
	}

	// Basic URL validation
	if !s.urlPattern.MatchString(urlStr) {
		return fmt.Errorf("invalid URL format: %s", urlStr)
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	host := parsed.Hostname()
	if err := s.ValidateResolvedIPStrict(host); err != nil {
		slog.Warn("Strict SSRF check blocked URL", "url", urlStr, "error", err)
		return fmt.Errorf("URL points to internal address: %s", urlStr)
	}

	return nil
}

// SanitizeShellArg sanitizes a shell argument to prevent injection.
func (s *Sanitizer) SanitizeShellArg(arg string) string {
	// Remove shell metacharacters
	result := strings.Map(func(r rune) rune {
		if isShellMetacharacter(r) {
			return -1 // Remove the character
		}
		return r
	}, arg)

	return strings.TrimSpace(result)
}

// ValidateInteger validates an integer value within a range.
func (s *Sanitizer) ValidateInteger(value int, min, max int) error {
	if value < min {
		return fmt.Errorf("value %d is below minimum %d", value, min)
	}
	if value > max {
		return fmt.Errorf("value %d is above maximum %d", value, max)
	}
	return nil
}

// containsShellMetacharacters checks if a string contains shell metacharacters.
func containsShellMetacharacters(s string) bool {
	for _, r := range s {
		if isShellMetacharacter(r) {
			return true
		}
	}
	return false
}

// containsShellMetacharactersForURL checks if a URL contains dangerous shell characters.
func containsShellMetacharactersForURL(s string) bool {
	dangerous := ";|`$()<>\"' \t\n\r"
	for _, r := range s {
		if strings.ContainsRune(dangerous, r) {
			return true
		}
	}
	return false
}

// isShellMetacharacter checks if a rune is a shell metacharacter.
func isShellMetacharacter(r rune) bool {
	shellMetacharacters := ";|&`$()<>{}[]\\\"' \t\n\r*?!"
	return strings.ContainsRune(shellMetacharacters, r)
}

// isInternalURL checks if a URL points to an internal address (SSRF protection).
func isInternalURL(urlStr string) bool {
	lowerURL := strings.ToLower(urlStr)
	if strings.HasPrefix(lowerURL, "file://") {
		return true
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		internalPatterns := []string{
			"http://localhost", "https://localhost",
			"http://127.", "https://127.",
			"http://0.", "https://0.",
			"http://[::1]", "https://[::1]",
			"http://169.254.", "https://169.254.",
			"http://192.168.", "https://192.168.",
			"http://10.", "https://10.",
		}
		for _, pattern := range internalPatterns {
			if strings.HasPrefix(lowerURL, pattern) {
				return true
			}
		}
		return false
	}

	host := parsed.Hostname()
	if strings.ToLower(host) == "localhost" {
		return true
	}

	if ip, ok := ParseMixedNotationIP(host); ok {
		return IsPrivateIP(ip)
	}

	if ip := net.ParseIP(host); ip != nil {
		return IsPrivateIP(ip)
	}

	return false
}

// ValidateCommandArgs validates command arguments for security.
func (s *Sanitizer) ValidateCommandArgs(args []string) error {
	for i, arg := range args {
		if arg == "" {
			continue // Empty args are typically OK
		}

		// Check for shell metacharacters
		if containsShellMetacharacters(arg) {
			return fmt.Errorf("argument %d contains shell metacharacters: %s", i, arg)
		}

		// Check for command chaining attempts
		if strings.Contains(arg, "&&") || strings.Contains(arg, "||") || strings.Contains(arg, ";") {
			return fmt.Errorf("argument %d contains command chaining: %s", i, arg)
		}

		// Check for variable substitution attempts
		if strings.Contains(arg, "$(") || strings.Contains(arg, "`") {
			return fmt.Errorf("argument %d contains command substitution: %s", i, arg)
		}
	}

	return nil
}

// SafeString converts a string to a safe representation for logging.
func (s *Sanitizer) SafeString(str string, maxLength int) string {
	if len(str) > maxLength {
		str = strings.TrimSpace(str[:maxLength]) + "..."
	}

	// Remove control characters
	result := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, str)

	return result
}

// ResolveAndValidateAddr resolves hostname, validates for SSRF, and returns pinned IP-based address and original host name.
func ResolveAndValidateAddr(ctx context.Context, addr string) (string, string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", "", err
	}

	var isIP bool
	var ipParsed net.IP
	if ip := net.ParseIP(host); ip != nil {
		isIP = true
		ipParsed = ip
	} else if ip, ok := ParseMixedNotationIP(host); ok {
		isIP = true
		ipParsed = ip
	}

	if isIP {
		if addrVal, err := netip.ParseAddr(ipParsed.String()); err == nil {
			if IsPrivateAddr(addrVal) {
				return "", "", fmt.Errorf("IP address is private/local: %s", addrVal.String())
			}
		} else if IsPrivateIP(ipParsed) {
			return "", "", fmt.Errorf("IP address is private/local: %s", ipParsed.String())
		}
		return net.JoinHostPort(ipParsed.String(), port), host, nil
	}

	ips, err := lookupIP(ctx, host)
	if err != nil {
		return "", "", fmt.Errorf("DNS resolution failed for %s: %w", host, err)
	}
	if len(ips) == 0 {
		return "", "", fmt.Errorf("no IP address found for %s", host)
	}

	for _, ip := range ips {
		if addrVal, err := netip.ParseAddr(ip.String()); err == nil {
			if IsPrivateAddr(addrVal) {
				return "", "", fmt.Errorf("host %s resolves to private IP %s", host, addrVal.String())
			}
		} else if IsPrivateIP(ip) {
			return "", "", fmt.Errorf("host %s resolves to private IP %s", host, ip.String())
		}
	}

	pinnedAddr := net.JoinHostPort(ips[0].String(), port)
	return pinnedAddr, host, nil
}

var secretRegexes = []*regexp.Regexp{
	regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                  // AWS Key
	regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`),             // Google API Key
	regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),      // Slack Token
	regexp.MustCompile(`gh[pso]_[a-zA-Z0-9]{36}`),            // GitHub Token
	regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),           // Stripe Key
	regexp.MustCompile(`(?i)(http|https)://(discord\.com/api/webhooks/|hooks\.slack\.com/services/)[^\s"']+`), // Webhooks
}

var (
	customSecretsMu sync.RWMutex
	customSecrets   []string
)

// RegisterSecretToRedact registers a specific sensitive value to be masked.
func RegisterSecretToRedact(secret string) {
	s := strings.TrimSpace(secret)
	if len(s) < 6 || s == "●●●●●●●●" {
		return // Avoid registering short/common keys or already redacted values
	}
	customSecretsMu.Lock()
	defer customSecretsMu.Unlock()
	// Prevent duplicate entries
	for _, existing := range customSecrets {
		if existing == s {
			return
		}
	}
	customSecrets = append(customSecrets, s)
}

// RedactSecrets scans a string and masks any detected secrets.
func RedactSecrets(text string) string {
	for _, re := range secretRegexes {
		text = re.ReplaceAllString(text, "●●●●●●●●")
	}
	customSecretsMu.RLock()
	defer customSecretsMu.RUnlock()
	for _, secret := range customSecrets {
		text = strings.ReplaceAll(text, secret, "●●●●●●●●")
	}
	return text
}


