package services

import (
	"sort"
	"strings"
)

type ToolDef struct {
	Name  string
	Stage int
	Tool  Tool
}

var toolRegistry = map[string]ToolDef{
	"amass":       {Name: "amass", Stage: 1, Tool: &AmassTool{}},
	"assetfinder": {Name: "assetfinder", Stage: 1, Tool: &AssetfinderTool{}},
	"crtsh":       {Name: "crtsh", Stage: 1, Tool: &CrtshTool{}},
	"httpx":       {Name: "httpx", Stage: 2, Tool: &HTTPXTool{}},
	"subfinder":   {Name: "subfinder", Stage: 1, Tool: &SubfinderTool{}},
	"findomain":   {Name: "findomain", Stage: 1, Tool: &FindomainTool{}},
	"massdns":     {Name: "massdns", Stage: 1, Tool: &MassdnsTool{}},
	"whois":       {Name: "whois", Stage: 1, Tool: &WhoisTool{}},
	"shodan":      {Name: "shodan", Stage: 2, Tool: &ShodanTool{}},
	"wafw00f":     {Name: "wafw00f", Stage: 2, Tool: &Wafw00fTool{}},
	"dnsx":        {Name: "dnsx", Stage: 2, Tool: &DNSXTool{}},
	"puredns":     {Name: "puredns", Stage: 1, Tool: &PurednsTool{}},
	"naabu":       {Name: "naabu", Stage: 2, Tool: &NaabuTool{}},
	"katana":      {Name: "katana", Stage: 3, Tool: &KatanaTool{}},
	"gau":         {Name: "gau", Stage: 3, Tool: &GauTool{}},
	"hakrawler":   {Name: "hakrawler", Stage: 3, Tool: &HakrawlerTool{}},
	"ffuf":        {Name: "ffuf", Stage: 4, Tool: &FFUFTool{}},
	"gobuster":    {Name: "gobuster", Stage: 4, Tool: &GobusterTool{}},
	"feroxbuster": {Name: "feroxbuster", Stage: 4, Tool: &FeroxbusterTool{}},
	"chaos":       {Name: "chaos", Stage: 1, Tool: &ChaosTool{}},
	"nuclei":      {Name: "nuclei", Stage: 5, Tool: &NucleiTool{}},
	"dalfox":      {Name: "dalfox", Stage: 5, Tool: &DalfoxTool{}},
	"trufflehog":  {Name: "trufflehog", Stage: 3, Tool: &TrufflehogTool{}},
	"interactsh":  {Name: "interactsh", Stage: 5, Tool: &InteractshTool{}},
	"uro":         {Name: "uro", Stage: 3, Tool: &UroTool{}},
	"cloudenum":   {Name: "cloudenum", Stage: 1, Tool: &CloudEnumTool{}},
	"graphql":     {Name: "graphql", Stage: 3, Tool: &GraphQLScanner{}},
	"secrets":     {Name: "secrets", Stage: 5, Tool: &SecretsTool{}},
	"browser":     {Name: "browser", Stage: 3, Tool: &BrowserRecon{}},
	"js_analyzer": {Name: "js_analyzer", Stage: 4, Tool: &JSAnalyzer{}},
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
	def, ok := toolRegistry[key]
	return def.Tool, ok
}

func GetToolStage(name string) int {
	key := normalizeToolName(name)
	if alias, ok := toolAliases[key]; ok {
		key = alias
	}
	if def, ok := toolRegistry[key]; ok {
		return def.Stage
	}
	return 3
}

func AvailableToolNames() []string {
	names := make([]string, 0, len(toolRegistry))
	for name := range toolRegistry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
