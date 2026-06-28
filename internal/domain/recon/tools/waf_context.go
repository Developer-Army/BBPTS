package tools

import "strings"

func wafBypassHeaders(waf string) []string {
	waf = strings.ToLower(strings.TrimSpace(waf))
	if waf == "" {
		return nil
	}
	headers := []string{
		"X-Forwarded-For: 127.0.0.1",
		"X-Originating-IP: 127.0.0.1",
		"X-Client-IP: 127.0.0.1",
		"X-Forwarded-Host: 127.0.0.1",
	}
	switch {
	case strings.Contains(waf, "cloudflare"):
		headers = append(headers, "CF-Connecting-IP: 127.0.0.1")
	case strings.Contains(waf, "akamai"):
		headers = append(headers, "Akamai-Origin-Hop: 1")
	case strings.Contains(waf, "aws") || strings.Contains(waf, "amazon"):
		headers = append(headers, "X-Amzn-Trace-Id: Root=1-00000000-000000000000000000000000")
	}
	return headers
}
