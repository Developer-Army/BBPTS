// Package normalize provides utilities for sanitizing and deduplicating targets.
package normalize

import (
	"net"
	"net/url"
	"sort"
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

	sort.Strings(normalized)
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

	sort.Strings(normalized)
	return normalized
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

	if ip := net.ParseIP(target); ip != nil {
		return ip.String()
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
