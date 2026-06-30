package tools

import (
	"context"
	"fmt"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

type SupplyChainTool struct{}

func (t *SupplyChainTool) Name() string {
	return "supply_chain"
}

func (t *SupplyChainTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 10
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

		client := NewSafeHTTPClient(10 * time.Second)
		var events []recon.Event

		events = append(events, t.checkJSBundles(ctx, client, target)...)

		events = append(events, t.checkDependencyFiles(ctx, client, target)...)

		events = append(events, t.checkCODEOWNERS(ctx, client, target)...)

		return events, nil
	})
}

func (t *SupplyChainTool) checkJSBundles(ctx context.Context, client *http.Client, target string) []recon.Event {
	var events []recon.Event

	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	bodyStr := string(body)

	jsPattern := regexp.MustCompile(`src=["']([^"']*\.js[^"']*)["']`)
	matches := jsPattern.FindAllStringSubmatch(bodyStr, 20)

	seenPackages := make(map[string]bool)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		jsPath := match[1]
		if !strings.HasPrefix(jsPath, "http") {
			jsPath = strings.TrimSuffix(target, "/") + "/" + strings.TrimPrefix(jsPath, "/")
		}

		jsReq, err := http.NewRequestWithContext(ctx, "GET", jsPath, nil)
		if err != nil {
			continue
		}
		jsResp, err := client.Do(jsReq)
		if err != nil {
			continue
		}
		jsBody, _ := io.ReadAll(io.LimitReader(jsResp.Body, 512*1024))
		jsResp.Body.Close()

		pkgPattern := regexp.MustCompile(`node_modules/([^/]+)/`)
		pkgMatches := pkgPattern.FindAllStringSubmatch(string(jsBody), 50)

		for _, pkgMatch := range pkgMatches {
			if len(pkgMatch) < 2 {
				continue
			}
			pkgName := pkgMatch[1]
			if seenPackages[pkgName] {
				continue
			}
			seenPackages[pkgName] = true

			if t.checkNPMPackage(ctx, client, pkgName) {
				events = append(events, recon.NewEvent(target, t.Name(), "supply_chain_package", map[string]string{
					"package":  pkgName,
					"source":   jsPath,
					"registry": "npm",
					"status":   "exists",
				}))
			}
		}

		events = append(events, t.checkTyposquats(ctx, client, target, seenPackages)...)
	}

	return events
}

func (t *SupplyChainTool) checkNPMPackage(ctx context.Context, client *http.Client, name string) bool {
	url := fmt.Sprintf("https://registry.npmjs.org/%s", name)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

func (t *SupplyChainTool) checkTyposquats(ctx context.Context, client *http.Client, target string, realPackages map[string]bool) []recon.Event {
	var events []recon.Event

	typos := map[string][]string{
		"lodash":     {"lodah", "lodas", "lodashs", "lodash-es", "_lodash"},
		"express":    {"expresss", "expres", "expressjs"},
		"react":      {"reactt", "reacat", "raect"},
		"axios":      {"axioos", "axiios", "axioss"},
		"moment":     {"momment", "momnet", "moments"},
		"webpack":    {"webackpack", "web pack", "webpackk"},
		"typescript": {"typscript", "typescrip", "typescripts"},
	}

	for realPkg, variants := range typos {
		if !realPackages[realPkg] {
			continue
		}
		for _, variant := range variants {
			if t.checkNPMPackage(ctx, client, variant) {
				events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
					"vuln_name":   "Potential Typosquatting Package",
					"severity":    "high",
					"real_pkg":    realPkg,
					"typosquat":   variant,
					"description": fmt.Sprintf("Package '%s' exists on npm and may be a typosquat of '%s'", variant, realPkg),
				}, "high"))
				slog.Warn("Typosquatting detected", "target", target, "real", realPkg, "fake", variant)
			}
		}
	}

	return events
}

func (t *SupplyChainTool) checkDependencyFiles(ctx context.Context, client *http.Client, target string) []recon.Event {
	var events []recon.Event

	depFiles := []string{
		"/package.json",
		"/package-lock.json",
		"/yarn.lock",
		"/requirements.txt",
		"/Pipfile.lock",
		"/Gemfile.lock",
		"/go.sum",
		"/composer.lock",
		"/poetry.lock",
		"/Cargo.lock",
	}

	base := strings.TrimSuffix(target, "/")
	for _, file := range depFiles {
		url := base + file
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == 200 {
			events = append(events, recon.NewEventWithSeverity(target, t.Name(), "vulnerability", map[string]string{
				"vuln_name":   "Exposed Dependency File",
				"severity":    "medium",
				"file":        file,
				"url":         url,
				"description": fmt.Sprintf("Dependency file %s is publicly accessible", file),
			}, "medium"))
		}
	}

	return events
}

func (t *SupplyChainTool) checkCODEOWNERS(ctx context.Context, client *http.Client, target string) []recon.Event {
	var events []recon.Event

	paths := []string{
		"/.github/CODEOWNERS",
		"/docs/CODEOWNERS",
		"/CODEOWNERS",
	}

	base := strings.TrimSuffix(target, "/")
	for _, path := range paths {
		url := base + path
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		if resp.StatusCode == 200 {

			bodyStr := string(body)
			lines := strings.Split(bodyStr, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					owner := parts[len(parts)-1]
					if strings.HasPrefix(owner, "@") && !strings.Contains(owner, "@github") {
						events = append(events, recon.NewEvent(target, t.Name(), "supply_chain_owner", map[string]string{
							"owner": owner,
							"path":  path,
							"rule":  line,
							"note":  "External account in CODEOWNERS - review for trust",
						}))
					}
				}
			}
		}
	}

	return events
}

var _ recon.Tool = (*SupplyChainTool)(nil)
