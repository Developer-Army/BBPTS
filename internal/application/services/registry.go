package services

import (
	"sort"
	"strings"
)

type ToolFactory func() Tool

var toolFactories = map[string]struct {
	factory func() Tool
	stage   int
}{
	"amass":       {factory: func() Tool { return &AmassTool{} }, stage: 1},
	"assetfinder": {factory: func() Tool { return &AssetfinderTool{} }, stage: 1},
	"crtsh":       {factory: func() Tool { return &CrtshTool{} }, stage: 1},
	"httpx":       {factory: func() Tool { return &HTTPXTool{} }, stage: 2},
	"subfinder":   {factory: func() Tool { return &SubfinderTool{} }, stage: 1},
	"findomain":   {factory: func() Tool { return &FindomainTool{} }, stage: 1},
	"massdns":     {factory: func() Tool { return &MassdnsTool{} }, stage: 1},
	"whois":       {factory: func() Tool { return &WhoisTool{} }, stage: 1},
	"shodan":      {factory: func() Tool { return &ShodanTool{} }, stage: 2},
	"wafw00f":     {factory: func() Tool { return &Wafw00fTool{} }, stage: 2},
	"dnsx":        {factory: func() Tool { return &DNSXTool{} }, stage: 2},
	"puredns":     {factory: func() Tool { return &PurednsTool{} }, stage: 1},
	"naabu":       {factory: func() Tool { return &NaabuTool{} }, stage: 2},
	"katana":      {factory: func() Tool { return &KatanaTool{} }, stage: 3},
	"gau":         {factory: func() Tool { return &GauTool{} }, stage: 3},
	"hakrawler":   {factory: func() Tool { return &HakrawlerTool{} }, stage: 3},
	"ffuf":        {factory: func() Tool { return &FFUFTool{} }, stage: 4},
	"gobuster":    {factory: func() Tool { return &GobusterTool{} }, stage: 4},
	"feroxbuster": {factory: func() Tool { return &FeroxbusterTool{} }, stage: 4},
	"chaos":       {factory: func() Tool { return &ChaosTool{} }, stage: 1},
	"nuclei":      {factory: func() Tool { return &NucleiTool{} }, stage: 5},
	"dalfox":      {factory: func() Tool { return &DalfoxTool{} }, stage: 5},
	"trufflehog":  {factory: func() Tool { return &TrufflehogTool{} }, stage: 3},
	"interactsh":  {factory: func() Tool { return &InteractshTool{} }, stage: 5},
	"uro":         {factory: func() Tool { return &UroTool{} }, stage: 3},
	"cloudenum":   {factory: func() Tool { return &CloudEnumTool{} }, stage: 1},
	"graphql":     {factory: func() Tool { return &GraphQLScanner{} }, stage: 3},
	"secrets":     {factory: func() Tool { return &SecretsTool{} }, stage: 5},
	"browser":     {factory: func() Tool { return &BrowserRecon{} }, stage: 3},
	"js_analyzer": {factory: func() Tool { return &JSAnalyzer{} }, stage: 4},
}

var toolAliases = map[string]string{
	"crt.sh":      "crtsh",
	"certificate": "crtsh",
	"wayback":     "gau",
	"waybackurls": "gau",
	"notes":       "gau",
	"subdomain":   "subfinder",
	"subdomains":  "subfinder",
	"recon":       "chaos",
	"vuln":        "nuclei",
	"scan":        "nuclei",
	"fuzz":        "ffuf",
	"brute":       "feroxbuster",
	"resolve":     "puredns",
	"crawler":     "browser",
	"spa":         "browser",
}

func normalizeToolName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func GetToolByName(name string) (Tool, bool) {
	key := normalizeToolName(name)
	if alias, ok := toolAliases[key]; ok {
		key = alias
	}
	if def, ok := toolFactories[key]; ok {
		return def.factory(), true
	}
	return nil, false
}

func GetToolStage(name string) int {
	key := normalizeToolName(name)
	if alias, ok := toolAliases[key]; ok {
		key = alias
	}
	if def, ok := toolFactories[key]; ok {
		return def.stage
	}
	return 3
}

func AvailableToolNames() []string {
	names := make([]string, 0, len(toolFactories))
	for name := range toolFactories {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
