package recon

import (
	"sort"
	"strings"
)

var toolRegistry = map[string]Tool{
	"amass":       &AmassTool{},
	"assetfinder": &AssetfinderTool{},
	"crtsh":       &CrtshTool{},
	"httpx":       &HTTPXTool{},
	"subfinder":   &SubfinderTool{},
	"dnsx":        &DNSXTool{},
	"puredns":     &PurednsTool{},
	"naabu":       &NaabuTool{},
	"katana":      &KatanaTool{},
	"waybackurls": &WaybackurlsTool{},
	"gau":         &GauTool{},
	"hakrawler":   &HakrawlerTool{},
	"ffuf":        &FFUFTool{},
	"gobuster":    &GobusterTool{},
	"feroxbuster": &FeroxbusterTool{},
	"chaos":       &ChaosTool{},
	"nuclei":      &NucleiTool{},
	"interactsh":  &InteractshTool{},
	"uro":         &UroTool{},
}

var toolAliases = map[string]string{
	"crt.sh":      "crtsh",
	"certificate": "crtsh",
	"wayback":     "waybackurls",
	"notes":       "waybackurls",
	"subdomain":   "subfinder",
	"subdomains":  "subfinder",
	"recon":       "chaos",
	"vuln":        "nuclei",
	"scan":        "nuclei",
	"fuzz":        "ffuf",
	"brute":       "feroxbuster",
	"resolve":     "puredns",
}

func normalizeToolName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func GetToolByName(name string) (Tool, bool) {
	key := normalizeToolName(name)
	if alias, ok := toolAliases[key]; ok {
		key = alias
	}
	tool, ok := toolRegistry[key]
	return tool, ok
}

func AvailableToolNames() []string {
	names := make([]string, 0, len(toolRegistry))
	for name := range toolRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
