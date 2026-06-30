package tools

import (
	"context"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"net/url"
	"sort"
	"strings"
)

type UroTool struct{}

func (t *UroTool) Name() string {
	return "uro"
}

func (t *UroTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
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

		ext := ""
		if idx := strings.LastIndex(parsed.Path, "."); idx != -1 {
			ext = strings.ToLower(parsed.Path[idx:])
		}
		if uselessExtensions[ext] {
			continue
		}

		query := parsed.Query()
		keys := make([]string, 0, len(query))
		for k := range query {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		fingerprint := parsed.Scheme + "://" + parsed.Host + parsed.Path
		if len(keys) > 0 {
			fingerprint += "?" + strings.Join(keys, "&")
		}

		if _, exists := seen[fingerprint]; !exists {
			seen[fingerprint] = struct{}{}
			cleaned = append(cleaned, target)
		}
	}

	events := make([]recon.Event, 0, len(cleaned))
	for _, u := range cleaned {
		events = append(events, recon.NewEvent(u, t.Name(), "cleaned_url", map[string]string{"type": "cleaned_url"}))
	}

	return events, nil
}
