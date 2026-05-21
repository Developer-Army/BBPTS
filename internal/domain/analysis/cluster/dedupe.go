// Package cluster groups recon events by normalized identity to reduce duplicate scoring.
package cluster

import (
	"net"
	"net/url"
	"sort"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// DedupeEvents merges reconnaissance events that describe the same logical target
// (same host and equivalent URL path/query) so downstream scoring is not inflated.
func DedupeEvents(events []recon.Event) []recon.Event {
	if len(events) <= 1 {
		return events
	}

	type bucket struct {
		canonical recon.Event
		sources   map[string]struct{}
	}

	groups := make(map[string]*bucket)

	for _, ev := range events {
		key := eventClusterKey(ev)
		g, ok := groups[key]
		if !ok {
			src := make(map[string]struct{})
			src[strings.TrimSpace(ev.Source)] = struct{}{}
			groups[key] = &bucket{
				canonical: ev,
				sources:   src,
			}
			continue
		}

		if ev.Source != "" {
			g.sources[strings.TrimSpace(ev.Source)] = struct{}{}
		}
		g.canonical = mergeEvents(g.canonical, ev)
	}

	out := make([]recon.Event, 0, len(groups))
	for _, g := range groups {
		ev := g.canonical
		if ev.Properties == nil {
			ev.Properties = make(map[string]string)
		}
		ev.Properties["bbpts_sources"] = joinSortedSources(g.sources)
		out = append(out, ev)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Target == out[j].Target {
			return out[i].Source < out[j].Source
		}
		return out[i].Target < out[j].Target
	})

	// Add structural fingerprint clustering
	ClusterByFingerprint(out)

	return out
}

func joinSortedSources(sources map[string]struct{}) string {
	list := make([]string, 0, len(sources))
	for s := range sources {
		if s != "" {
			list = append(list, s)
		}
	}
	sort.Strings(list)
	return strings.Join(list, ",")
}

func mergeEvents(a, b recon.Event) recon.Event {
	out := a
	if len(b.Target) > len(out.Target) {
		out.Target = b.Target
	}
	if out.Properties == nil {
		out.Properties = make(map[string]string)
	}
	if b.Properties != nil {
		for k, v := range b.Properties {
			if k == "severity" {
				out.Properties[k] = maxSeverity(out.Properties[k], v)
				continue
			}
			if _, ok := out.Properties[k]; !ok && v != "" {
				out.Properties[k] = v
			}
		}
	}
	out.Type = pickRicherType(out.Type, b.Type)
	return out
}

func pickRicherType(x, y string) string {
	if y != "" && x == "" {
		return y
	}
	return x
}

func maxSeverity(a, b string) string {
	order := map[string]int{
		"critical": 5,
		"high":     4,
		"medium":   3,
		"low":      2,
		"info":     1,
	}
	la := strings.ToLower(strings.TrimSpace(a))
	lb := strings.ToLower(strings.TrimSpace(b))
	if order[lb] > order[la] {
		return lb
	}
	return la
}

func eventClusterKey(ev recon.Event) string {
	raw := strings.TrimSpace(ev.Target)
	if raw == "" {
		return "|"
	}

	u := tryParseURL(raw)
	if u != nil && u.Host != "" {
		host := strings.ToLower(u.Hostname())
		path := strings.TrimSpace(u.Path)
		if path == "" {
			path = "/"
		}
		q := normalizedQueryKey(u)
		return host + "|" + path + "|" + q
	}

	return strings.ToLower(hostOnly(raw)) + "||"
}

func tryParseURL(raw string) *url.URL {
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}
	return u
}

func normalizedQueryKey(u *url.URL) string {
	q := u.Query()
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		parts = append(parts, k+"="+strings.Join(vals, ","))
	}
	return strings.Join(parts, "&")
}

func hostOnly(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u := tryParseURL(raw)
	if u != nil && u.Host != "" {
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(raw)
}
