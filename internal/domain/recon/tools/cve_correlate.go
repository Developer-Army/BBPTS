package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type CVECorrelateTool struct{}

func (t *CVECorrelateTool) Name() string {
	return "cve_correlate"
}

type cisaKEVFeed struct {
	Vulnerabilities []cisaCVE `json:"vulnerabilities"`
}

type cisaCVE struct {
	CVEID             string `json:"cveID"`
	VendorProject     string `json:"vendorProject"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerabilityName"`
	ShortDescription  string `json:"shortDescription"`
}

var (
	cisaKevURL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	localKevCache = filepath.Join("results", "cisa_kev.json")
	kevCacheMu    sync.Mutex
)

func (t *CVECorrelateTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	kev, err := t.loadKEV(ctx)
	if err != nil {
		slog.Warn("cve_correlate: failed to load CISA KEV feed", "error", err)
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 50
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		store := storage.FromContext(ctx)
		if store == nil {
			return nil, nil
		}

		dbEvents, err := store.GetEventsByTarget(target)
		if err != nil {
			return nil, nil
		}

		var events []recon.Event

		for _, dbEv := range dbEvents {
			if dbEv.Source != "httpx" || dbEv.Type != "service" {
				continue
			}

			server := dbEv.Properties["server"]
			techsStr := dbEv.Properties["technologies"]

			var techList []string
			if server != "" {
				techList = append(techList, server)
			}
			if techsStr != "" {
				techList = append(techList, strings.Split(techsStr, ",")...)
			}

			for _, tech := range techList {
				tech = strings.TrimSpace(tech)
				if tech == "" {
					continue
				}

				name, version := parseTechVersion(tech)
				if name == "" || version == "" {
					continue
				}

				matches := correlateKEV(name, version, kev)
				for _, match := range matches {
					events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
						"vuln_name":   fmt.Sprintf("Known Exploited Vulnerability: %s (%s)", match.CVEID, name),
						"severity":    "critical",
						"cve":         match.CVEID,
						"product":     match.Product,
						"tech":        tech,
						"evidence":    fmt.Sprintf("Version %s matches CVE %s description: %s", version, match.CVEID, match.VulnerabilityName),
						"description": fmt.Sprintf("Exposed service running %s version %s is vulnerable to %s. Description: %s", name, version, match.CVEID, match.ShortDescription),
					}, "critical"))
				}
			}
		}

		return events, nil
	})
}

func (t *CVECorrelateTool) loadKEV(ctx context.Context) (*cisaKEVFeed, error) {
	kevCacheMu.Lock()
	defer kevCacheMu.Unlock()

	if fi, err := os.Stat(localKevCache); err == nil {
		if time.Since(fi.ModTime()) < 24*time.Hour {

			fBytes, err := os.ReadFile(localKevCache)
			if err == nil {
				var feed cisaKEVFeed
				if err := json.Unmarshal(fBytes, &feed); err == nil {
					return &feed, nil
				}
			}
		}
	}

	client := NewSafeHTTPClient(15 * time.Second)
	req, err := http.NewRequestWithContext(ctx, "GET", cisaKevURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var feed cisaKEVFeed
	if err := json.Unmarshal(bodyBytes, &feed); err != nil {
		return nil, err
	}

	_ = os.MkdirAll(filepath.Dir(localKevCache), 0700)
	_ = os.WriteFile(localKevCache, bodyBytes, 0644)

	return &feed, nil
}

func parseTechVersion(tech string) (string, string) {
	tech = strings.ToLower(tech)
	parts := strings.Split(tech, "/")
	if len(parts) == 2 {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}

	parts = strings.Fields(tech)
	if len(parts) >= 2 {

		v := parts[len(parts)-1]
		if isVersionString(v) {
			name := strings.Join(parts[:len(parts)-1], " ")
			return strings.TrimSpace(name), strings.TrimSpace(v)
		}
	}

	return "", ""
}

func isVersionString(s string) bool {
	matched, _ := regexp.MatchString(`^[0-9]+(\.[0-9]+)*(-[a-zA-Z0-9.]+)?$`, s)
	return matched
}

func correlateKEV(product, version string, feed *cisaKEVFeed) []cisaCVE {
	if feed == nil {
		return nil
	}

	product = strings.ToLower(product)
	var matches []cisaCVE

	for _, v := range feed.Vulnerabilities {
		prod := strings.ToLower(v.Product)
		vendor := strings.ToLower(v.VendorProject)

		if strings.Contains(prod, product) || strings.Contains(product, prod) || strings.Contains(vendor, product) {

			desc := strings.ToLower(v.ShortDescription)
			if versionMatchesDescription(version, desc) {
				matches = append(matches, v)
			}
		}
	}

	return matches
}

func versionMatchesDescription(version, desc string) bool {

	versionClean := strings.ReplaceAll(version, ".", `\.`)
	reStr := fmt.Sprintf(`\b%s\b`, versionClean)
	if matched, _ := regexp.MatchString(reStr, desc); matched {
		return true
	}

	vParts := parseVersionParts(version)
	if len(vParts) == 0 {
		return true
	}

	reBefore := regexp.MustCompile(`(?:before|prior\s+to|versions\s+less\s+than)\s+([0-9]+(?:\.[0-9]+)*)`)
	matches := reBefore.FindAllStringSubmatch(desc, -1)
	for _, m := range matches {
		if len(m) > 1 {
			targetParts := parseVersionParts(m[1])
			if compareVersions(vParts, targetParts) < 0 {
				return true
			}
		}
	}

	return !strings.Contains(desc, "before") && !strings.Contains(desc, "prior")
}

func parseVersionParts(v string) []int {
	v = regexp.MustCompile(`[^0-9.]`).ReplaceAllString(v, "")
	parts := strings.Split(v, ".")
	var res []int
	for _, p := range parts {
		if p == "" {
			continue
		}
		var val int
		_, _ = fmt.Sscanf(p, "%d", &val)
		res = append(res, val)
	}
	return res
}

func compareVersions(v1, v2 []int) int {
	for i := 0; i < len(v1) && i < len(v2); i++ {
		if v1[i] < v2[i] {
			return -1
		}
		if v1[i] > v2[i] {
			return 1
		}
	}
	if len(v1) < len(v2) {
		return -1
	}
	if len(v1) > len(v2) {
		return 1
	}
	return 0
}

var _ recon.Tool = (*CVECorrelateTool)(nil)
