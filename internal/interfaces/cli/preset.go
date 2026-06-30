package cli

import (
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

const (
	ModeLight  = "light"
	ModeNormal = "normal"
)

func ApplyPresetAndProfileDefaults(opts *Options, cfg *config.Config) {
	if opts == nil || cfg == nil {
		return
	}
	mode := ResolveMode(*opts)
	if opts.Tools != "" {
		if modeFlagActive(*opts) {
			opts.Tools = ToolsetForMode(mode)
		}
		applyProfileRateOnly(opts, cfg)
		return
	}

	if modeFlagActive(*opts) {
		opts.Tools = ToolsetForMode(mode)
		applyProfileRateOnly(opts, cfg)
		return
	}

	if cfg.ToolPresets != nil && opts.Preset != "" {
		if pr, ok := cfg.ToolPresets[opts.Preset]; ok && pr.Tools != "" {
			opts.Tools = pr.Tools
			if pr.RateLimit > 0 {
				opts.RateLimit = pr.RateLimit
			}
			if pr.Timeout != "" {
				if d, err := time.ParseDuration(pr.Timeout); err == nil {
					opts.Timeout = d
				}
			}
			applyProfileRateOnly(opts, cfg)
			return
		}
	}

	if cfg.ProgramProfiles != nil && opts.Profile != "" {
		if pp, ok := cfg.ProgramProfiles[opts.Profile]; ok && pp.Tools != "" {
			opts.Tools = pp.Tools
			if pp.RateLimit > 0 {
				opts.RateLimit = pp.RateLimit
			}
			if pp.Timeout != "" {
				if d, err := time.ParseDuration(pp.Timeout); err == nil {
					opts.Timeout = d
				}
			}
			applyProfileRateOnly(opts, cfg)
			return
		}
	}

	opts.Tools = ToolsetForMode(ModeNormal)
	applyProfileRateOnly(opts, cfg)
}

func ResolveMode(opts Options) string {
	if opts.LightMode {
		return ModeLight
	}
	if opts.FullMode {
		return ModeNormal
	}
	switch strings.ToLower(strings.TrimSpace(opts.Mode)) {
	case ModeLight:
		return ModeLight
	case ModeNormal, "full", "":
		return ModeNormal
	default:
		return ModeNormal
	}
}

func modeFlagActive(opts Options) bool {
	return opts.LightMode || opts.FullMode || strings.TrimSpace(opts.Mode) != ""
}

func ToolsetForMode(mode string) string {
	switch mode {
	case ModeLight:
		return strings.Join(LightModeTools(), ",")
	default:
		return strings.Join(NormalModeTools(), ",")
	}
}

func LightModeTools() []string {
	return []string{
		"crtsh", "subfinder", "amass", "assetfinder", "chaos",
		"puredns", "dnsx", "massdns", "whois",
		"naabu", "httpx", "shodan",
		"katana", "gau", "hakrawler",
		"uro", "dalfox", "nuclei", "interactsh", "secrets",
		"trufflehog", "browser", "js_analyzer", "gowitness", "tlsx", "github",
		"cloud_buckets",
		"takeover",
		"graphql",
		"oauth",
		"proto_pollution",
		"websocket",
		"smuggling",
		"race",
		"cache_poisoning",
		"ai_vuln",
		"idor_assist",
		"github_dorker", "github_actions", "github_org_discovery",
		"mobile_static", "app_store_recon",
		"cors", "jwt_analyzer", "bypass403",
		"firebase_recon", "mass_assignment", "source_map", "default_creds",
		"asn_recon", "cve_correlate", "grpc_probe", "git_exposure",
		"web3_recon", "paste_leaks", "cert_monitor", "price_logic", "dep_audit",
		"soap_probe", "mobile_recon", "cloud_exposure",
		"blind_inject", "business_logic", "second_order", "redos", "supply_chain",
		"tenant_isolate", "auth_matrix", "ratelimit_bypass", "wordlist_gen",
	}
}

func NormalModeTools() []string {
	return []string{
		"crtsh", "subfinder", "amass", "assetfinder", "chaos",
		"puredns", "dnsx", "massdns", "whois",
		"naabu", "httpx", "shodan",
		"katana", "gau", "hakrawler", "ffuf", "gobuster", "feroxbuster",
		"uro", "dalfox", "nuclei", "interactsh", "secrets",
		"trufflehog", "browser", "js_analyzer", "gowitness", "tlsx", "github",
		"cloud_buckets",
		"takeover",
		"graphql",
		"oauth",
		"proto_pollution",
		"websocket",
		"smuggling",
		"race",
		"cache_poisoning",
		"ai_vuln",
		"idor_assist",
		"ssrf",
		"crlf",
		"email_header_injection",
		"api_version_probe",
		"jsonp",
		"webdav",
		"dns_zone_transfer",
		"http2_downgrade",
		"tls_misconfig",
		"github_dorker", "github_actions", "github_vuln_scanning",
		"github_org_discovery", "github_private_repos",
		"mobile_static", "mobile_dynamic", "mobile_api_discovery", "app_store_recon",
		"cors", "jwt_analyzer", "bypass403",
		"firebase_recon", "mass_assignment", "source_map", "default_creds",
		"asn_recon", "cve_correlate", "grpc_probe", "git_exposure",
		"web3_recon", "paste_leaks", "cert_monitor", "price_logic", "dep_audit",
		"soap_probe", "mobile_recon", "cloud_exposure",
		"blind_inject", "business_logic", "second_order", "redos", "supply_chain",
		"tenant_isolate", "auth_matrix", "ratelimit_bypass", "wordlist_gen",
	}
}

func OptionalToolNamesForDoctor(mode string) []string {
	if mode != ModeNormal && mode != "full" {
		return nil
	}
	required := map[string]struct{}{}
	for _, name := range strings.Split(ToolsetForMode(mode), ",") {
		required[name] = struct{}{}
	}
	var optional []string
	for _, name := range services.AvailableToolNames() {
		if _, ok := required[name]; !ok {
			optional = append(optional, name)
		}
	}
	return optional
}

func applyProfileRateOnly(opts *Options, cfg *config.Config) {
	if cfg.ProgramProfiles == nil || opts.Profile == "" {
		return
	}
	pp, ok := cfg.ProgramProfiles[opts.Profile]
	if !ok || pp.RateLimit <= 0 || opts.RateLimit != 0 {
		return
	}
	opts.RateLimit = pp.RateLimit
}

func FilterExcludedTools(tools []string, exclude string) []string {
	if strings.TrimSpace(exclude) == "" {
		return tools
	}
	excluded := make(map[string]struct{})
	for _, name := range strings.Split(exclude, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name != "" {
			excluded[name] = struct{}{}
		}
	}
	filtered := make([]string, 0, len(tools))
	for _, t := range tools {
		if _, skip := excluded[strings.ToLower(strings.TrimSpace(t))]; !skip {
			filtered = append(filtered, t)
		}
	}
	return filtered
}
