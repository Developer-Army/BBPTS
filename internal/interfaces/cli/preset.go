package cli

import (
	"strings"
	"time"

	"github.com/Developer-Army/BBPTS/internal/application/services"
	"github.com/Developer-Army/BBPTS/internal/shared/config"
)

const (
	ModeLight  = "light"
	ModeMedium = "medium"
	ModeFull   = "full"
)

// ApplyPresetAndProfileDefaults sets opts.Tools (and optional rate/timeout) when the
// operator did not pass -tools. Preset takes precedence over program profile.
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

	opts.Tools = ToolsetForMode(ModeMedium)
	applyProfileRateOnly(opts, cfg)
}

func ResolveMode(opts Options) string {
	if opts.FullMode {
		return ModeFull
	}
	if opts.LightMode {
		return ModeLight
	}
	switch strings.ToLower(strings.TrimSpace(opts.Mode)) {
	case ModeLight:
		return ModeLight
	case ModeFull:
		return ModeFull
	case ModeMedium, "":
		return ModeMedium
	default:
		return ModeMedium
	}
}

func modeFlagActive(opts Options) bool {
	return opts.LightMode || opts.FullMode || strings.TrimSpace(opts.Mode) != ""
}

func ToolsetForMode(mode string) string {
	switch mode {
	case ModeLight:
		return strings.Join(LightModeTools(), ",")
	case ModeFull:
		return strings.Join(FullModeTools(), ",")
	default:
		return strings.Join(MediumModeTools(), ",")
	}
}

func LightModeTools() []string {
	return []string{
		"crtsh", "subfinder", "httpx",
	}
}

func MediumModeTools() []string {
	return []string{
		"crtsh", "subfinder", "puredns", "dnsx",
		"naabu", "httpx",
		"katana", "gau", "ffuf", "feroxbuster",
		"uro", "dalfox", "nuclei",
	}
}

func FullModeTools() []string {
	return []string{
		"crtsh", "subfinder", "amass", "assetfinder", "findomain", "chaos",
		"puredns", "dnsx", "massdns", "whois",
		"naabu", "httpx", "wafw00f", "shodan",
		"katana", "gau", "hakrawler", "ffuf", "gobuster", "feroxbuster",
		"uro", "dalfox", "nuclei", "interactsh", "secrets",
		"trufflehog", "browser", "js_analyzer",
	}
}

func OptionalToolNamesForDoctor(mode string) []string {
	if mode != ModeFull {
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
