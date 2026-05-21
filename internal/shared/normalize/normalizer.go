// Package normalize provides utilities for sanitizing and deduplicating targets.
package normalize

import (
	"net"
	"net/url"
	"strings"
)

// DeduplicateAndNormalize processes a list of raw target strings, cleaning up
// whitespace, removing URL schemes, extracting hosts, and removing duplicates.
func DeduplicateAndNormalize(inputs []string) []string {
	seen := make(map[string]struct{}, len(inputs))
	normalized := make([]string, 0, len(inputs))

	for _, raw := range inputs {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}

		normalizedTarget := normalizeTarget(item)
		if normalizedTarget == "" {
			continue
		}
		if _, ok := seen[normalizedTarget]; ok {
			continue
		}
		seen[normalizedTarget] = struct{}{}
		normalized = append(normalized, normalizedTarget)
	}

	return normalized
}

// DeduplicateAndPreserveURLs keeps fully-qualified web URLs intact while still
// normalizing plain hosts/IPs for staged pipeline handoff.
func DeduplicateAndPreserveURLs(inputs []string) []string {
	seen := make(map[string]struct{}, len(inputs))
	normalized := make([]string, 0, len(inputs))

	for _, raw := range inputs {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}

		normalizedTarget := normalizeTargetPreservingURL(item)
		if normalizedTarget == "" {
			continue
		}
		if _, ok := seen[normalizedTarget]; ok {
			continue
		}
		seen[normalizedTarget] = struct{}{}
		normalized = append(normalized, normalizedTarget)
	}

	return normalized
}

func IsValidDomain(host string) bool {
	if host == "" || len(host) > 255 {
		return false
	}
	// Basic syntax validation
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		for _, char := range part {
			if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-') {
				return false
			}
		}
	}
	// The last part (TLD) must not be purely numeric and must be at least 2 chars
	lastPart := parts[len(parts)-1]
	if len(lastPart) < 2 {
		return false
	}
	allNumeric := true
	for _, char := range lastPart {
		if char < '0' || char > '9' {
			allNumeric = false
			break
		}
	}
	return !allNumeric
}

func normalizeTarget(target string) string {
	target = strings.TrimSpace(target)

	// If it's a full URL, extract the host/port
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
			host := parsed.Host
			if parsed.Scheme == "https" && strings.HasSuffix(host, ":443") {
				host = strings.TrimSuffix(host, ":443")
			}
			if parsed.Scheme == "http" && strings.HasSuffix(host, ":80") {
				host = strings.TrimSuffix(host, ":80")
			}
			target = host
		}
	} else {
		// Not a URL with scheme. Check for CIDR before stripping paths
		if _, _, err := net.ParseCIDR(target); err == nil {
			return strings.ToLower(target)
		}

		// Remove path if present
		if idx := strings.Index(target, "/"); idx != -1 {
			target = target[:idx]
		}
	}

	// Handle host + port
	hostPart := target
	if idx := strings.LastIndex(target, ":"); idx != -1 {
		// Check if it's an IPv6 address with port or just a normal IPv6 address
		if !strings.Contains(target, "]") && strings.Count(target, ":") > 1 {
			// Plain IPv6 without brackets
		} else {
			hostPart = target[:idx]
			// remove brackets for IPv6
			hostPart = strings.TrimPrefix(hostPart, "[")
			hostPart = strings.TrimSuffix(hostPart, "]")
		}
	}

	// Try parsing as IP address (both IPv4 and IPv6)
	if ip := net.ParseIP(hostPart); ip != nil {
		return target
	}

	// Reject invalid targets/domains
	if !IsValidDomain(hostPart) {
		return ""
	}

	return strings.ToLower(strings.TrimSpace(target))
}

func normalizeTargetPreservingURL(target string) string {
	target = strings.TrimSpace(target)
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" {
			return ""
		}

		parsed.Scheme = strings.ToLower(parsed.Scheme)
		parsed.Host = strings.ToLower(parsed.Host)
		if parsed.Scheme == "https" && strings.HasSuffix(parsed.Host, ":443") {
			parsed.Host = strings.TrimSuffix(parsed.Host, ":443")
		}
		if parsed.Scheme == "http" && strings.HasSuffix(parsed.Host, ":80") {
			parsed.Host = strings.TrimSuffix(parsed.Host, ":80")
		}
		if parsed.Path == "/" {
			parsed.Path = ""
		}
		parsed.Fragment = ""
		return parsed.String()
	}

	return normalizeTarget(target)
}
