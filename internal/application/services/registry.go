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
	"amass":           {factory: func() Tool { return &AmassTool{} }, stage: 1},
	"assetfinder":     {factory: func() Tool { return &AssetfinderTool{} }, stage: 1},
	"github_dorker":   {factory: func() Tool { return &GithubDorkerTool{} }, stage: 0},
	"email_enum":      {factory: func() Tool { return &EmailEnumTool{} }, stage: 0},
	"crtsh":           {factory: func() Tool { return &CrtshTool{} }, stage: 1},
	"httpx":           {factory: func() Tool { return &HTTPXTool{} }, stage: 3},
	"subfinder":       {factory: func() Tool { return &SubfinderTool{} }, stage: 1},
	"github":          {factory: func() Tool { return &GithubTool{} }, stage: 1},
	"massdns":         {factory: func() Tool { return &MassdnsTool{} }, stage: 2},
	"whois":           {factory: func() Tool { return &WhoisTool{} }, stage: 1},
	"shodan":          {factory: func() Tool { return &ShodanTool{} }, stage: 3},
	"wafw00f":         {factory: func() Tool { return &Wafw00fTool{} }, stage: 3},
	"tlsx":            {factory: func() Tool { return &TLSXTool{} }, stage: 1},
	"dnsx":            {factory: func() Tool { return &DNSXTool{} }, stage: 2},
	"puredns":         {factory: func() Tool { return &PurednsTool{} }, stage: 2},
	"naabu":           {factory: func() Tool { return &NaabuTool{} }, stage: 2},
	"permutation":     {factory: func() Tool { return &PermutationTool{} }, stage: 2},
	"katana":          {factory: func() Tool { return &KatanaTool{} }, stage: 3},
	"gau":             {factory: func() Tool { return &GauTool{} }, stage: 3},
	"hakrawler":       {factory: func() Tool { return &HakrawlerTool{} }, stage: 3},
	"ffuf":            {factory: func() Tool { return &FFUFTool{} }, stage: 4},
	"gobuster":        {factory: func() Tool { return &GobusterTool{} }, stage: 4},
	"gowitness":       {factory: func() Tool { return &GowitnessTool{} }, stage: 3},
	"feroxbuster":     {factory: func() Tool { return &FeroxbusterTool{} }, stage: 4},
	"chaos":           {factory: func() Tool { return &ChaosTool{} }, stage: 1},
	"nuclei":          {factory: func() Tool { return &NucleiTool{} }, stage: 4},
	"dalfox":          {factory: func() Tool { return &DalfoxTool{} }, stage: 4},
	"trufflehog":      {factory: func() Tool { return &TrufflehogTool{} }, stage: 3},
	"interactsh":      {factory: func() Tool { return &InteractshTool{} }, stage: 4},
	"uro":             {factory: func() Tool { return &UroTool{} }, stage: 3},
	"graphql":         {factory: func() Tool { return &GraphQLScanner{} }, stage: 3},
	"secrets":         {factory: func() Tool { return &SecretsTool{} }, stage: 4},
	"browser":         {factory: func() Tool { return &BrowserRecon{} }, stage: 3},
	"js_analyzer":     {factory: func() Tool { return &JSAnalyzer{} }, stage: 4},
	"cloud_buckets":   {factory: func() Tool { return &CloudBucketsTool{} }, stage: 1},
	"takeover":        {factory: func() Tool { return &TakeoverTool{} }, stage: 3},
	"cors":            {factory: func() Tool { return &CORSTool{} }, stage: 4},
	"bypass403":       {factory: func() Tool { return &Bypass403Tool{} }, stage: 3},
	"jwt_analyzer":    {factory: func() Tool { return &JWTAnalyzerTool{} }, stage: 4},
	"open_redirect":   {factory: func() Tool { return &OpenRedirectTool{} }, stage: 4},
	"arjun":           {factory: func() Tool { return &ArjunTool{} }, stage: 3},
	"oauth":           {factory: func() Tool { return &OAuthTesterTool{} }, stage: 4},
	"proto_pollution": {factory: func() Tool { return &ProtoPollutionTool{} }, stage: 4},
	"websocket":       {factory: func() Tool { return &WebSocketTool{} }, stage: 3},
	"smuggling":       {factory: func() Tool { return &SmugglingTool{} }, stage: 3},
	"race":            {factory: func() Tool { return &RaceTool{} }, stage: 4},
	"cache_poisoning": {factory: func() Tool { return &CachePoisoningTool{} }, stage: 4},
	"ai_vuln":         {factory: func() Tool { return &AIVulnTool{} }, stage: 4},
	"idor_assist":     {factory: func() Tool { return &IDORAssistTool{} }, stage: 4},
	"sqlmap":          {factory: func() Tool { return &SQLMapTool{} }, stage: 4},
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
	"bucket":      "cloud_buckets",
	"s3":          "cloud_buckets",
	"cloud":       "cloud_buckets",
	"subjack":     "takeover",
	"subtake":     "takeover",
	"dorker":      "github_dorker",
	"dork":        "github_dorker",
	"ghrecon":     "github_dorker",
	"email":       "email_enum",
	"emails":      "email_enum",
	"hunter":      "email_enum",
	"prompt":      "ai_vuln",
	"injection":   "ai_vuln",
	"idor":        "idor_assist",
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
