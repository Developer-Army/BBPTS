package services

import (
	"context"
	"net/url"
	"sort"
	"strings"
)

// UroTool implements native Go URL normalization and deduplication,
// replacing the slower Python uro tool for faster pipeline execution.
type UroTool struct{}

func (t *UroTool) Name() string {
	return "uro"
}

func (t *UroTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	uselessExtensions := map[string]bool{
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true,
		".css": true, ".js": true, ".ico": true, ".woff": true, ".woff2": true,
		".ttf": true, ".eot": true, ".svg": true, ".mp4": true, ".mp3": true,
		".wav": true, ".avi": true, ".mov": true, ".pdf": true, ".zip": true,
		".tar": true, ".gz": true, ".rar": true, ".7z": true,
	}

	seen := make(map[string]struct{})
	var cleaned []string

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		parsed, err := url.Parse(target)
		if err != nil || parsed.Host == "" {
			continue
		}

		// Skip useless extensions
		ext := ""
		if idx := strings.LastIndex(parsed.Path, "."); idx != -1 {
			ext = strings.ToLower(parsed.Path[idx:])
		}
		if uselessExtensions[ext] {
			continue
		}

		// Normalize query parameters (keep keys, discard values for deduplication)
		query := parsed.Query()
		keys := make([]string, 0, len(query))
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Create a fingerprint for deduplication
		fingerprint := parsed.Scheme + "://" + parsed.Host + parsed.Path
		if len(keys) > 0 {
			fingerprint += "?" + strings.Join(keys, "&")
		}

		if _, exists := seen[fingerprint]; !exists {
			seen[fingerprint] = struct{}{}
			cleaned = append(cleaned, target) // Keep original URL, just first one seen
		}
	}

	events := make([]Event, 0, len(cleaned))
	for _, u := range cleaned {
		events = append(events, NewEvent(u, t.Name(), "cleaned_url", map[string]string{"type": "cleaned_url"}))
	}

	return events, nil
}
