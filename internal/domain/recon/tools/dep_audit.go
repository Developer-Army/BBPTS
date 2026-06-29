package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type DepAuditTool struct{}

func (t *DepAuditTool) Name() string {
	return "dep_audit"
}

// A simple dictionary mapping package names to known vulnerable versions
// and their associated details.
type vulnPackage struct {
	MaxVulnerableVersion []int
	CVE                  string
	Severity             string
	Description          string
}

var knownVulnPackages = map[string]vulnPackage{
	"jquery": {
		MaxVulnerableVersion: []int{3, 5, 0},
		CVE:                  "CVE-2020-11022",
		Severity:             "medium",
		Description:          "jQuery before 3.5.0 is vulnerable to Cross-Site Scripting (XSS) via passing HTML containing <option> elements to manipulation methods.",
	},
	"lodash": {
		MaxVulnerableVersion: []int{4, 17, 20},
		CVE:                  "CVE-2020-8203",
		Severity:             "high",
		Description:          "lodash before 4.17.21 is vulnerable to Prototype Pollution via zipObjectDeep.",
	},
	"bootstrap": {
		MaxVulnerableVersion: []int{4, 3, 0},
		CVE:                  "CVE-2019-8331",
		Severity:             "medium",
		Description:          "Bootstrap before 4.3.1 is vulnerable to Cross-Site Scripting (XSS) in tooltip/popover data-template.",
	},
}

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (t *DepAuditTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 20
	}
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, targets, func(ctx context.Context, target string) ([]recon.Event, error) {
		target = strings.TrimSpace(target)
		if target == "" {
			return nil, nil
		}

		if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
			target = "https://" + target
		}

		parsed, err := url.Parse(target)
		if err != nil {
			return nil, nil
		}

		client := NewSafeHTTPClient(5 * time.Second)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}

		var events []recon.Event

		// Audit paths
		auditPaths := []string{
			"/package.json",
			"/static/package.json",
		}

		for _, aPath := range auditPaths {
			pkgURL := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, aPath)
			req, err := http.NewRequestWithContext(ctx, "GET", pkgURL, nil)
			if err != nil {
				continue
			}
			for k, v := range scanCtx.Headers {
				req.Header.Set(k, v)
			}

			resp, err := client.Do(req)
			if err == nil {
				bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
				resp.Body.Close()

				if resp.StatusCode == http.StatusOK {
					var pkg packageJSON
					if err := json.Unmarshal(bodyBytes, &pkg); err == nil {
						allDeps := make(map[string]string)
						for k, v := range pkg.Dependencies {
							allDeps[k] = v
						}
						for k, v := range pkg.DevDependencies {
							allDeps[k] = v
						}

						for name, versionVal := range allDeps {
							nameClean := strings.ToLower(name)
							if vuln, exists := knownVulnPackages[nameClean]; exists {
								versionClean := cleanVersionString(versionVal)
								vParts := parseVersionParts(versionClean)
								if len(vParts) > 0 && compareVersions(vParts, vuln.MaxVulnerableVersion) <= 0 {
									// Vulnerable package found!
									events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
										"vuln_name":   fmt.Sprintf("Vulnerable Dependency: %s (%s)", name, vuln.CVE),
										"severity":    vuln.Severity,
										"url":         pkgURL,
										"package":     name,
										"version":     versionVal,
										"cve":         vuln.CVE,
										"evidence":    fmt.Sprintf("%s: %s", name, versionVal),
										"description": fmt.Sprintf("Public package file at %s exposes vulnerable package %s version %s. Details: %s", pkgURL, name, versionVal, vuln.Description),
									}, vuln.Severity))
								}
							}
						}
					}
				}
			}
		}

		return events, nil
	})
}

func cleanVersionString(v string) string {
	// Remove prefixes like ^, ~, >=, <=, *
	v = strings.TrimPrefix(v, "^")
	v = strings.TrimPrefix(v, "~")
	v = strings.TrimPrefix(v, ">=")
	v = strings.TrimPrefix(v, "<=")
	v = regexp.MustCompile(`[^0-9.]`).ReplaceAllString(v, "")
	return v
}

var _ recon.Tool = (*DepAuditTool)(nil)
