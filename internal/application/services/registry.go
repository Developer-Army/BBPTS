package services

import (
	"sort"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon/tools"
)

type ToolFactory func() Tool

var toolFactories = map[string]struct {
	factory func() Tool
	stage   int
}{
	"amass":           {factory: func() Tool { return &tools.AmassTool{} }, stage: 1},
	"assetfinder":     {factory: func() Tool { return &tools.AssetfinderTool{} }, stage: 1},
	"github_dorker":   {factory: func() Tool { return &tools.GithubDorkerTool{} }, stage: 0},
	"email_enum":      {factory: func() Tool { return &tools.EmailEnumTool{} }, stage: 0},
	"crtsh":           {factory: func() Tool { return &tools.CrtshTool{} }, stage: 1},
	"httpx":           {factory: func() Tool { return &tools.HTTPXTool{} }, stage: 3},
	"subfinder":       {factory: func() Tool { return &tools.SubfinderTool{} }, stage: 1},
	"github":          {factory: func() Tool { return &tools.GithubTool{} }, stage: 1},
	"massdns":         {factory: func() Tool { return &tools.MassdnsTool{} }, stage: 2},
	"whois":           {factory: func() Tool { return &tools.WhoisTool{} }, stage: 1},
	"shodan":          {factory: func() Tool { return &tools.ShodanTool{} }, stage: 3},
	"wafw00f":         {factory: func() Tool { return &tools.Wafw00fTool{} }, stage: 3},
	"tlsx":            {factory: func() Tool { return &tools.TLSXTool{} }, stage: 1},
	"dnsx":            {factory: func() Tool { return &tools.DNSXTool{} }, stage: 2},
	"puredns":         {factory: func() Tool { return &tools.PurednsTool{} }, stage: 2},
	"naabu":           {factory: func() Tool { return &tools.NaabuTool{} }, stage: 2},
	"permutation":     {factory: func() Tool { return &tools.PermutationTool{} }, stage: 2},
	"katana":          {factory: func() Tool { return &tools.KatanaTool{} }, stage: 3},
	"gau":             {factory: func() Tool { return &tools.GauTool{} }, stage: 3},
	"hakrawler":       {factory: func() Tool { return &tools.HakrawlerTool{} }, stage: 3},
	"ffuf":            {factory: func() Tool { return &tools.FFUFTool{} }, stage: 4},
	"gobuster":        {factory: func() Tool { return &tools.GobusterTool{} }, stage: 4},
	"gowitness":       {factory: func() Tool { return &tools.GowitnessTool{} }, stage: 3},
	"feroxbuster":     {factory: func() Tool { return &tools.FeroxbusterTool{} }, stage: 4},
	"chaos":           {factory: func() Tool { return &tools.ChaosTool{} }, stage: 1},
	"nuclei":          {factory: func() Tool { return &tools.NucleiTool{} }, stage: 4},
	"dalfox":          {factory: func() Tool { return &tools.DalfoxTool{} }, stage: 4},
	"trufflehog":      {factory: func() Tool { return &tools.TrufflehogTool{} }, stage: 3},
	"interactsh":      {factory: func() Tool { return &tools.InteractshTool{} }, stage: 4},
	"uro":             {factory: func() Tool { return &tools.UroTool{} }, stage: 3},
	"graphql":         {factory: func() Tool { return &tools.GraphQLScanner{} }, stage: 3},
	"secrets":         {factory: func() Tool { return &tools.SecretsTool{} }, stage: 4},
	"browser":         {factory: func() Tool { return &tools.BrowserRecon{} }, stage: 3},
	"js_analyzer":     {factory: func() Tool { return &tools.JSAnalyzer{} }, stage: 4},
	"cloud_buckets":   {factory: func() Tool { return &tools.CloudBucketsTool{} }, stage: 1},
	"takeover":        {factory: func() Tool { return &tools.TakeoverTool{} }, stage: 3},
	"cors":            {factory: func() Tool { return &tools.CORSTool{} }, stage: 4},
	"bypass403":       {factory: func() Tool { return &tools.Bypass403Tool{} }, stage: 3},
	"jwt_analyzer":    {factory: func() Tool { return &tools.JWTAnalyzerTool{} }, stage: 4},
	"open_redirect":   {factory: func() Tool { return &tools.OpenRedirectTool{} }, stage: 4},
	"arjun":           {factory: func() Tool { return &tools.ArjunTool{} }, stage: 3},
	"oauth":           {factory: func() Tool { return &tools.OAuthTesterTool{} }, stage: 4},
	"proto_pollution": {factory: func() Tool { return &tools.ProtoPollutionTool{} }, stage: 4},
	"websocket":       {factory: func() Tool { return &tools.WebSocketTool{} }, stage: 3},
	"smuggling":       {factory: func() Tool { return &tools.SmugglingTool{} }, stage: 3},
	"race":            {factory: func() Tool { return &tools.RaceTool{} }, stage: 4},
	"cache_poisoning":       {factory: func() Tool { return &tools.CachePoisoningTool{} }, stage: 4},
	"ai_vuln":               {factory: func() Tool { return &tools.AIVulnTool{} }, stage: 4},
	"idor_assist":           {factory: func() Tool { return &tools.IDORAssistTool{} }, stage: 4},
	"sqlmap":                {factory: func() Tool { return &tools.SQLMapTool{} }, stage: 4},
	"ssrf":                  {factory: func() Tool { return &tools.SSRFTool{} }, stage: 4},
	"crlf":                  {factory: func() Tool { return &tools.CRLFTool{} }, stage: 4},
	"email_header_injection":{factory: func() Tool { return &tools.EmailHeaderInjectionTool{} }, stage: 4},
	"api_version_probe":     {factory: func() Tool { return &tools.APIVersionProbeTool{} }, stage: 4},
	"jsonp":                 {factory: func() Tool { return &tools.JSONPTool{} }, stage: 4},
	"webdav":                {factory: func() Tool { return &tools.WebDAVTool{} }, stage: 4},
	"dns_zone_transfer":     {factory: func() Tool { return &tools.DNSZoneTransferTool{} }, stage: 4},
	"http2_downgrade":       {factory: func() Tool { return &tools.HTTP2DowngradeTool{} }, stage: 4},
	"tls_misconfig":         {factory: func() Tool { return &tools.TLSMisconfigTool{} }, stage: 4},
	"mobile_static":         {factory: func() Tool { return &tools.MobileStaticTool{} }, stage: 1},
	"mobile_dynamic":        {factory: func() Tool { return &tools.MobileDynamicTool{} }, stage: 4},
	"mobile_api_discovery":  {factory: func() Tool { return &tools.MobileAPIDiscoveryTool{} }, stage: 3},
	"app_store_recon":       {factory: func() Tool { return &tools.AppStoreReconTool{} }, stage: 0},
	"github_actions":        {factory: func() Tool { return &tools.GithubActionsTool{} }, stage: 0},
	"github_vuln_scanning":  {factory: func() Tool { return &tools.GithubVulnScanningTool{} }, stage: 1},
	"github_org_discovery":  {factory: func() Tool { return &tools.GithubOrgDiscoveryTool{} }, stage: 0},
	"github_private_repos":  {factory: func() Tool { return &tools.GithubPrivateReposTool{} }, stage: 0},
	"firebase_recon":       {factory: func() Tool { return &tools.FirebaseReconTool{} }, stage: 3},
	"mass_assignment":      {factory: func() Tool { return &tools.MassAssignmentTool{} }, stage: 4},
	"source_map":           {factory: func() Tool { return &tools.SourceMapTool{} }, stage: 3},
	"default_creds":        {factory: func() Tool { return &tools.DefaultCredsTool{} }, stage: 4},
	"asn_recon":            {factory: func() Tool { return &tools.ASNReconTool{} }, stage: 1},
	"cve_correlate":        {factory: func() Tool { return &tools.CVECorrelateTool{} }, stage: 4},
	"grpc_probe":           {factory: func() Tool { return &tools.GRPCProbeTool{} }, stage: 4},
	"git_exposure":         {factory: func() Tool { return &tools.GitExposureTool{} }, stage: 4},
	"web3_recon":           {factory: func() Tool { return &tools.Web3ReconTool{} }, stage: 3},
	"paste_leaks":          {factory: func() Tool { return &tools.PasteLeaksTool{} }, stage: 0},
	"cert_monitor":         {factory: func() Tool { return &tools.CertMonitorTool{} }, stage: 1},
	"price_logic":          {factory: func() Tool { return &tools.PriceLogicTool{} }, stage: 4},
	"dep_audit":            {factory: func() Tool { return &tools.DepAuditTool{} }, stage: 4},
	"soap_probe":           {factory: func() Tool { return &tools.SOAPProbeTool{} }, stage: 3},
	"mobile_recon":         {factory: func() Tool { return &tools.MobileReconTool{} }, stage: 3},
	"cloud_exposure":       {factory: func() Tool { return &tools.CloudExposureTool{} }, stage: 3},
	"auth_matrix":          {factory: func() Tool { return &tools.AuthMatrixTool{} }, stage: 4},
	"ratelimit_bypass":     {factory: func() Tool { return &tools.RateLimitBypassTool{} }, stage: 4},
	"blind_inject":         {factory: func() Tool { return &tools.BlindInjectTool{} }, stage: 4},
	"business_logic":       {factory: func() Tool { return &tools.BusinessLogicTool{} }, stage: 4},
	"wordlist_gen":         {factory: func() Tool { return &tools.WordlistGenTool{} }, stage: 1},
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
	"idor":               "idor_assist",
	"mobile":             "mobile_static",
	"mobile_app":         "mobile_static",
	"static_analysis":    "mobile_static",
	"static":             "mobile_static",
	"frida":              "mobile_dynamic",
	"objection":          "mobile_dynamic",
	"dynamic":            "mobile_dynamic",
	"appstore":           "app_store_recon",
	"app_store":          "app_store_recon",
	"apple_store":        "app_store_recon",
	"play_store":         "app_store_recon",
	"api_discovery":      "mobile_api_discovery",
	"actions":            "github_actions",
	"ci_analysis":        "github_actions",
	"workflow":           "github_actions",
	"dependabot":         "github_vuln_scanning",
	"codeql":             "github_vuln_scanning",
	"vuln_scan":          "github_vuln_scanning",
	"org":                "github_org_discovery",
	"organization":       "github_org_discovery",
	"members":            "github_org_discovery",
	"private":            "github_private_repos",
	"private_repos":      "github_private_repos",
	"gh_private":         "github_private_repos",
	"firebase":           "firebase_recon",
	"firestore":          "firebase_recon",
	"rtdb":               "firebase_recon",
	"mass_assign":        "mass_assignment",
	"massassign":         "mass_assignment",
	"sourcemap":          "source_map",
	"jsmap":              "source_map",
	"default_passwords":  "default_creds",
	"creds":              "default_creds",
	"weak_creds":         "default_creds",
	"wordlist":           "wordlist_gen",
	"custom_wordlist":    "wordlist_gen",
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
