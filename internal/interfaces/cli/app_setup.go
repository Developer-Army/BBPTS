package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/interfaces/ui/tui"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
	"github.com/Developer-Army/BBPTS/internal/shared/input"
	"github.com/Developer-Army/BBPTS/internal/shared/normalize"
	"github.com/Developer-Army/BBPTS/internal/shared/utils"
)

// isDirectURL reports whether the -i value looks like a URL or hostname
// that should be used as a target directly, rather than treated as a file path.
func isDirectURL(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	// Has a scheme (http://, https://) — treat as a URL target
	if strings.Contains(s, "://") {
		return true
	}
	// Bare hostname: contains at least one dot, no path separators,
	// and does not look like a common plain-file extension.
	if !strings.Contains(s, "/") && !strings.Contains(s, `\`) {
		lower := strings.ToLower(s)
		for _, ext := range fileExtsThatMightBeURLs {
			if strings.HasSuffix(lower, ext) {
				return false
			}
		}
		if strings.Contains(s, ".") {
			return true
		}
	}
	return false
}

// fileExtsThatMightBeURLs lists file extensions that should NOT be treated as
// bare URL targets. Used so that a hostname named "hostname.txt" (a file)
// isn't mistaken for a target, while "acme-corp.io" still is.
var fileExtsThatMightBeURLs = []string{
	".txt", ".csv", ".json", ".yaml", ".yml", ".xml", ".toml", ".conf",
	".log", ".jsonl", ".env", ".md", ".input",
}

var wildcardCache sync.Map

func detectWildcardIPs(ctx context.Context, parent string) []string {
	if ips, ok := wildcardCache.Load(parent); ok {
		return ips.([]string)
	}

	randHost := fmt.Sprintf("bbpts-wildcard-%d.%s", time.Now().UnixNano(), parent)
	var resolver net.Resolver
	ips, err := resolver.LookupIP(ctx, "ip", randHost)
	var ipStrings []string
	if err == nil {
		for _, ip := range ips {
			ipStrings = append(ipStrings, ip.String())
		}
	}
	if ipStrings == nil {
		ipStrings = []string{}
	}
	wildcardCache.Store(parent, ipStrings)
	return ipStrings
}

func getParentDomain(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func validateTargetsWithHTTPX(ctx context.Context, targets []string, threads int) ([]string, []recon.Event) {
	slog.Info("Probing input targets to verify active hosts...", "count", len(targets))

	var alive []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Create a semaphore to cap parallel lookups to 50
	sem := make(chan struct{}, 50)

	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			cleanHost := target
			if strings.Contains(cleanHost, "://") {
				parts := strings.SplitN(cleanHost, "://", 2)
				cleanHost = parts[1]
			}
			if idx := strings.Index(cleanHost, "/"); idx != -1 {
				cleanHost = cleanHost[:idx]
			}
			if idx := strings.LastIndex(cleanHost, ":"); idx != -1 {
				if !(strings.Count(cleanHost, ":") > 1 && !strings.Contains(cleanHost, "]")) {
					cleanHost = cleanHost[:idx]
					cleanHost = strings.TrimPrefix(cleanHost, "[")
					cleanHost = strings.TrimSuffix(cleanHost, "]")
				}
			}

			// If it's a direct IP, it's alive
			if net.ParseIP(cleanHost) != nil {
				mu.Lock()
				alive = append(alive, target)
				mu.Unlock()
				return
			}

			// Try DNS lookup to see if it resolves
			ips, err := net.LookupIP(cleanHost)
			if err == nil && len(ips) > 0 {
				parent := getParentDomain(cleanHost)
				wildcardIPs := detectWildcardIPs(ctx, parent)
				isWildcard := false
				if len(wildcardIPs) > 0 {
					matchCount := 0
					for _, ip := range ips {
						ipStr := ip.String()
						for _, wIP := range wildcardIPs {
							if ipStr == wIP {
								matchCount++
								break
							}
						}
					}
					if matchCount == len(ips) {
						isWildcard = true
					}
				}

				if isWildcard {
					slog.Warn("Target filtered out as wildcard DNS subdomain", "target", cleanHost)
					return
				}

				mu.Lock()
				alive = append(alive, target)
				mu.Unlock()
			} else {
				slog.Warn("Target failed DNS resolution", "target", cleanHost)
			}
		}(target)
	}
	wg.Wait()

	if len(alive) == 0 {
		slog.Warn("No targets resolved via DNS lookup.")
		return nil, nil
	}

	// Sort alive list to keep deterministic order
	sort.Strings(alive)

	httpxTool := &services.HTTPXTool{}
	events, err := httpxTool.Run(ctx, alive, threads)
	if err != nil {
		slog.Warn("Target validation via httpx failed or skipped; proceeding with DNS-resolved targets", "error", err)
		return alive, nil
	}
	if len(events) == 0 {
		slog.Warn("No targets returned active status via httpx; proceeding with DNS-resolved targets")
		return alive, nil
	}

	var validated []string
	seen := make(map[string]struct{})
	for _, ev := range events {
		targetVal := strings.TrimSpace(ev.Target)
		if targetVal != "" {
			if _, ok := seen[targetVal]; !ok {
				seen[targetVal] = struct{}{}
				validated = append(validated, targetVal)
			}
		}
	}
	slog.Info("Target validation completed successfully", "active_targets", len(validated))
	return validated, convertServicesEventsToRecon(events)
}

func defaultReportPaths(inputPath string) (string, string) {
	base := strings.TrimSpace(filepath.Base(inputPath))
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if strings.TrimSpace(name) == "" {
		name = "scan"
	}
	return filepath.Join("results", name+"_report.md"), filepath.Join("results", name+"_summary.csv")
}

func writeSeedDomainsToTmp(tmpDir string, targets []string) error {
	if strings.TrimSpace(tmpDir) == "" {
		return nil
	}
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return err
	}

	domains := extractSeedDomains(targets)
	if len(domains) == 0 {
		return nil
	}

	path := filepath.Join(tmpDir, "seed_domains.txt")
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, domain := range domains {
		if _, err := writer.WriteString(domain + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func extractSeedDomains(targets []string) []string {
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))

	for _, target := range targets {
		domain := domainFromTarget(target)
		if domain == "" {
			continue
		}
		if _, ok := seen[domain]; ok {
			continue
		}
		seen[domain] = struct{}{}
		out = append(out, domain)
	}
	return out
}

func domainFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}

	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return ""
		}
		host := strings.ToLower(strings.Split(u.Host, ":")[0])
		if !isValidSeedHostname(host) {
			return ""
		}
		return host
	}

	trimmed := strings.Split(target, "/")[0]
	if strings.Contains(trimmed, " ") {
		return ""
	}
	host := strings.ToLower(strings.Split(trimmed, ":")[0])
	if !isValidSeedHostname(host) {
		return ""
	}
	return host
}

func isValidSeedHostname(host string) bool {
	host = strings.Trim(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" || strings.ContainsAny(host, " /\\") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func scanTimeout(perTool time.Duration, toolCount int) time.Duration {
	if perTool <= 0 {
		return 0
	}
	if toolCount < 1 {
		toolCount = 1
	}
	return perTool * time.Duration(toolCount)
}

func resolveTmpResultsDir(opts Options, cfg *config.Config) string {
	if opts.LightMode {
		return filepath.Join("results", "tmp")
	}
	if cfg != nil && strings.TrimSpace(cfg.TmpResultsDir) != "" {
		return cfg.TmpResultsDir
	}

	baseDir := "."
	if strings.TrimSpace(opts.OutputPath) != "" {
		baseDir = filepath.Dir(opts.OutputPath)
	} else if strings.TrimSpace(opts.SummaryPath) != "" {
		baseDir = filepath.Dir(opts.SummaryPath)
	}
	if baseDir == "results" || baseDir == "./results" {
		return filepath.Join(baseDir, "tmp")
	}
	return filepath.Join(baseDir, "results", "tmp")
}

func writeModePipelineArtifacts(outputDir string, seedTargets []string, events []recon.Event) error {
	if strings.TrimSpace(outputDir) == "" {
		return nil
	}
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return err
	}

	rootDomains := extractSeedDomains(seedTargets)
	if err := writeLines(filepath.Join(outputDir, "root_domains.txt"), rootDomains); err != nil {
		return err
	}

	passive := make([]string, 0)
	resolved := make([]string, 0)
	liveHosts := make([]string, 0)
	services := make([]string, 0)
	combined := make([]string, 0)
	normalized := make([]string, 0)

	for _, ev := range events {
		target := strings.TrimSpace(ev.Target)
		if target == "" {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(ev.Source))
		switch source {
		case "assetfinder", "crtsh", "subfinder", "chaos":
			passive = append(passive, domainFromTarget(target))
		case "dnsx":
			resolved = append(resolved, domainFromTarget(target))
		case "httpx":
			if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
				liveHosts = append(liveHosts, target)
			}
		case "naabu":
			services = append(services, target)
		case "gau", "katana", "hakrawler", "feroxbuster", "ffuf":
			if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
				combined = append(combined, target)
			}
		case "uro":
			if strings.HasPrefix(strings.ToLower(target), "http://") || strings.HasPrefix(strings.ToLower(target), "https://") {
				normalized = append(normalized, target)
			}
		}
	}

	passive = append(passive, rootDomains...)
	if err := writeLines(filepath.Join(outputDir, "recon.txt"), passive); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "resolved_subdomains.txt"), resolved); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "live_hosts.txt"), liveHosts); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "services.txt"), services); err != nil {
		return err
	}
	if err := writeLines(filepath.Join(outputDir, "combined_urls.txt"), combined); err != nil {
		return err
	}
	if len(normalized) == 0 {
		normalized = combined
	}
	return writeLines(filepath.Join(outputDir, "normalized_urls.txt"), normalized)
}

func writeLines(path string, lines []string) error {
	seen := make(map[string]struct{}, len(lines))
	clean := make([]string, 0, len(lines))
	for _, line := range lines {
		v := strings.TrimSpace(line)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		clean = append(clean, v)
	}
	sort.Strings(clean)

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	for _, line := range clean {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func handlePersistence(opts Options, cfg *config.Config, normalized []string, events []recon.Event) (*utils.Diff, error) {
	if opts.Scope == "" {
		return nil, nil
	}
	store, err := utils.NewStore(cfg.StateDir, true)
	if err != nil {
		slog.Error("failed to open utils store", "error", err)
		return nil, err
	}
	defer store.Close()

	diff, err := store.ComputeDiff(opts.Scope, normalized, events)
	if err != nil {
		slog.Warn("failed to compute diff", "error", err)
	}

	if err := store.Save(opts.Scope, normalized, events); err != nil {
		slog.Error("failed to save utils", "error", err)
	}

	if diff != nil && opts.DiffOnly {
		slog.Info("diff computed", "new_targets", len(diff.NewTargets), "new_events", len(diff.NewEvents))
	}

	return diff, nil
}

func convertServicesEventsToRecon(events []services.Event) []recon.Event {
	out := make([]recon.Event, len(events))
	for i, ev := range events {
		out[i] = recon.Event{
			Target:     ev.Target,
			Source:     ev.Source,
			Type:       ev.Type,
			Properties: ev.Properties,
		}
	}
	return out
}

func parseAndValidateTargets(ctx context.Context, opts *Options, cfg *config.Config, bridge *tui.Bridge, reconThreads int) ([]string, []recon.Event, bool) {
	var normalized []string
	var validationEvents []recon.Event

	if opts.InputPath != "" {
		if isDirectURL(opts.InputPath) {
			normalized = []string{opts.InputPath}
		} else {
			if strings.TrimSpace(opts.OutputPath) == "" && strings.TrimSpace(opts.SummaryPath) == "" {
				opts.OutputPath, opts.SummaryPath = defaultReportPaths(opts.InputPath)
				slog.Info("no report paths provided; using defaults", "output", opts.OutputPath, "summary", opts.SummaryPath)
			}

			if bridge != nil {
				bridge.ReportToolStatus("engine", "running", "parsing input targets")
			}
			parser := input.NewParser()
			metadataTargets, err := parser.ParseFileWithMetadata(opts.InputPath)
			if err != nil {
				slog.Error("failed to parse input", "error", err)
				if bridge != nil {
					bridge.ReportFailure("engine", "failed to parse input")
				}
				return nil, nil, false
			}

			rawTargets := make([]string, 0, len(metadataTargets))
			for _, target := range metadataTargets {
				if !target.IsInScope() {
					continue
				}
				rawTargets = append(rawTargets, target.URL)
			}

			normalized = normalize.DeduplicateAndPreserveURLs(rawTargets)
			if len(normalized) == 0 {
				slog.Warn("no in-scope targets were found in the input file")
				if bridge != nil {
					bridge.ReportFailure("engine", "no in-scope targets found")
				}
				return nil, nil, false
			}
		}
		if bridge != nil {
			bridge.SendInitialTargets(normalized)
		}
	} else if bridge != nil {
		bridge.PromptForTarget()
		select {
		case targets := <-tui.TargetInputChan:
			select {
			case selectedMode := <-tui.TargetModeChan:
				opts.Mode = selectedMode
				opts.LightMode = (selectedMode == "light")
				opts.FullMode = (selectedMode == "normal")
			default:
				opts.Mode = "normal"
			}
			opts.Tools = ToolsetForMode(opts.Mode)
			normalized = targets
			if strings.TrimSpace(opts.OutputPath) == "" && strings.TrimSpace(opts.SummaryPath) == "" {
				opts.OutputPath, opts.SummaryPath = defaultReportPaths(targets[0])
				slog.Info("no report paths provided; using defaults", "output", opts.OutputPath, "summary", opts.SummaryPath)
			}
			bridge.SendInitialTargets(normalized)
		case <-ctx.Done():
			return nil, nil, false
		}
	}

	// Expand company: or asn: targets if present
	if len(normalized) > 0 {
		var expanded []string
		for _, target := range normalized {
			target = strings.TrimSpace(target)
			if strings.HasPrefix(strings.ToLower(target), "company:") {
				comp := strings.TrimPrefix(target, "company:")
				slog.Info("expanding company to ASN and IP ranges", "company", comp)
				if cidrs, err := expandCompanyTargets(comp); err == nil && len(cidrs) > 0 {
					expanded = append(expanded, cidrs...)
					slog.Info("expanded company to CIDR ranges", "company", comp, "count", len(cidrs))
				} else {
					slog.Warn("failed to expand company to CIDRs", "company", comp, "error", err)
					expanded = append(expanded, target)
				}
			} else if strings.HasPrefix(strings.ToLower(target), "asn:") {
				asnStr := strings.TrimPrefix(target, "asn:")
				var asn int
				if _, err := fmt.Sscanf(asnStr, "%d", &asn); err == nil {
					slog.Info("expanding ASN to IP ranges", "asn", asn)
					if cidrs, err := expandASNPrefixes(asn); err == nil && len(cidrs) > 0 {
						expanded = append(expanded, cidrs...)
						slog.Info("expanded ASN to CIDR ranges", "asn", asn, "count", len(cidrs))
					} else {
						slog.Warn("failed to expand ASN to CIDRs", "asn", asn, "error", err)
						expanded = append(expanded, target)
					}
				} else {
					expanded = append(expanded, target)
				}
			} else {
				expanded = append(expanded, target)
			}
		}
		normalized = expanded
	}

	if opts.ScopeFile != "" && len(normalized) > 0 {
		se, err := input.LoadScopeFile(opts.ScopeFile)
		if err != nil {
			slog.Error("failed to load scope file", "path", opts.ScopeFile, "error", err)
			if bridge != nil {
				bridge.ReportFailure("engine", "failed to load scope file")
			}
			return nil, nil, false
		}
		var filtered []string
		for _, t := range normalized {
			if se.IsInScope(t) {
				filtered = append(filtered, t)
			} else {
				slog.Info("target out of scope, skipping", "target", t)
			}
		}
		normalized = filtered
	}

	if len(normalized) > 0 {
		if opts.PassiveMode {
			slog.Info("Passive mode enabled: skipping active target validation via httpx")
		} else {
			normalized, validationEvents = validateTargetsWithHTTPX(ctx, normalized, reconThreads)
			if len(normalized) == 0 {
				slog.Warn("No valid targets active or resolved via httpx validation. Aborting run.")
				if bridge != nil {
					bridge.ReportFailure("engine", "all targets failed validation")
				}
				return nil, nil, false
			}
		}
	}

	if len(normalized) > 0 {
		if opts.Profile != "" && cfg.ProgramProfiles != nil {
			if prof, ok := cfg.ProgramProfiles[opts.Profile]; ok {
				before := len(normalized)
				normalized = config.FilterTargets(normalized, prof)
				if before != len(normalized) {
					slog.Info("program profile applied", "profile", opts.Profile, "targets_after_filter", len(normalized))
				}
				if len(normalized) == 0 {
					slog.Warn("all targets excluded by program profile", "profile", opts.Profile)
					return nil, nil, false
				}
			}
		}
	}

	return normalized, validationEvents, true
}

type bgpSearchResponse struct {
	Status string `json:"status"`
	Data   struct {
		ASNs []struct {
			ASN  int    `json:"asn"`
			Name string `json:"name"`
		} `json:"asns"`
	} `json:"data"`
}

type bgpPrefixResponse struct {
	Status string `json:"status"`
	Data   struct {
		IPv4 []struct {
			Prefix string `json:"prefix"`
		} `json:"ipv4_prefixes"`
	} `json:"data"`
}

func expandCompanyTargets(company string) ([]string, error) {
	client := services.NewSafeHTTPClient(10 * time.Second)
	searchURL := fmt.Sprintf("https://api.bgpview.io/search?query_term=%s", url.QueryEscape(company))
	resp, err := client.Get(searchURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bgpview returned status %d", resp.StatusCode)
	}

	var searchResult bgpSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&searchResult); err != nil {
		return nil, err
	}

	var expanded []string
	asns := searchResult.Data.ASNs
	if len(asns) > 5 {
		asns = asns[:5]
	}

	for _, asn := range asns {
		prefixes, err := expandASNPrefixes(asn.ASN)
		if err == nil {
			expanded = append(expanded, prefixes...)
		}
	}

	return expanded, nil
}

func expandASNPrefixes(asn int) ([]string, error) {
	client := services.NewSafeHTTPClient(10 * time.Second)
	prefixURL := fmt.Sprintf("https://api.bgpview.io/asn/%d/prefixes", asn)
	pResp, err := client.Get(prefixURL)
	if err != nil {
		return nil, err
	}
	defer pResp.Body.Close()

	if pResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bgpview prefix endpoint returned status %d", pResp.StatusCode)
	}

	var prefixResult bgpPrefixResponse
	if err := json.NewDecoder(pResp.Body).Decode(&prefixResult); err != nil {
		return nil, err
	}

	var expanded []string
	for _, p := range prefixResult.Data.IPv4 {
		expanded = append(expanded, p.Prefix)
	}
	return expanded, nil
}
