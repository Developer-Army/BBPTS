package normalize

import (
	"net"
	"net/url"
	"strings"
)

// ScopeGuard ensures no external or forbidden assets bleed into the active pipeline.
type ScopeGuard struct {
	allowedDomains []string
	allowedIPs     map[string]struct{}
	allowedCIDRs   []*net.IPNet
}

func NewScopeGuard(inScopeDomains []string) *ScopeGuard {
	sg := &ScopeGuard{
		allowedDomains: make([]string, 0, len(inScopeDomains)),
		allowedIPs:     make(map[string]struct{}),
		allowedCIDRs:   make([]*net.IPNet, 0),
	}
	seenDomains := make(map[string]struct{}, len(inScopeDomains))

	for _, raw := range inScopeDomains {
		clean := normalizeScopeTarget(raw)
		if clean == "" {
			continue
		}

		if ip := net.ParseIP(clean); ip != nil {
			sg.allowedIPs[ip.String()] = struct{}{}
			continue
		}

		if _, cidr, err := net.ParseCIDR(clean); err == nil {
			sg.allowedCIDRs = append(sg.allowedCIDRs, cidr)
			continue
		}

		clean = strings.TrimPrefix(clean, "*.")
		if _, ok := seenDomains[clean]; ok {
			continue
		}
		seenDomains[clean] = struct{}{}
		sg.allowedDomains = append(sg.allowedDomains, clean)
	}
	return sg
}

// IsAllowed returns true ONLY if the target strictly belongs to an allowed domain.
func (sg *ScopeGuard) IsAllowed(target string) bool {
	if len(sg.allowedDomains) == 0 && len(sg.allowedIPs) == 0 && len(sg.allowedCIDRs) == 0 {
		return true
	}

	cleanTarget := normalizeScopeTarget(target)
	if cleanTarget == "" {
		return false
	}

	if ip := net.ParseIP(cleanTarget); ip != nil {
		if _, ok := sg.allowedIPs[ip.String()]; ok {
			return true
		}
		for _, cidr := range sg.allowedCIDRs {
			if cidr.Contains(ip) {
				return true
			}
		}
		return false
	}

	for _, allowed := range sg.allowedDomains {
		if cleanTarget == allowed || strings.HasSuffix(cleanTarget, "."+allowed) {
			return true
		}
	}
	return false
}

// Filter out all out-of-scope targets from a slice
func (sg *ScopeGuard) Filter(targets []string) []string {
	safe := make([]string, 0, len(targets))
	for _, t := range targets {
		if sg.IsAllowed(t) {
			safe = append(safe, t)
		}
	}
	return safe
}

func normalizeScopeTarget(target string) string {
	clean := strings.ToLower(strings.TrimSpace(target))
	if clean == "" {
		return ""
	}

	if strings.Contains(clean, "://") {
		parsed, err := url.Parse(clean)
		if err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}

	if ip := net.ParseIP(clean); ip != nil {
		return ip.String()
	}

	if _, _, err := net.ParseCIDR(clean); err == nil {
		return clean
	}

	if host, _, err := net.SplitHostPort(clean); err == nil && host != "" {
		return strings.ToLower(host)
	}

	if idx := strings.Index(clean, "/"); idx != -1 {
		clean = clean[:idx]
	}

	return strings.TrimPrefix(clean, "*.")
}
