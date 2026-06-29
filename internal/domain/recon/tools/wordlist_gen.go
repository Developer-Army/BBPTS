package tools

import (
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/time/rate"
)

type WordlistGenTool struct{}

// Tech path vocabulary: tech keyword -> list of paths to add
var techPaths = map[string][]string{
	"wordpress":  {"wp-json", "wp-admin", "wp-cron.php", "xmlrpc.php", "wp-login.php", "wp-content", "wp-includes"},
	"rails":      {"rails/info", "rails/mailers", "letter_opener", "sidekiq", "delayed_job"},
	"spring":     {"actuator", "actuator/env", "actuator/heapdump", "actuator/mappings", "actuator/configprops", "actuator/beans"},
	"django":     {"admin/", "__debug__/", "api/schema/", "api/docs/", "static/", "media/"},
	"laravel":    {"_ignition/", "storage/logs/laravel.log", "telescope", "horizon", "nova"},
	"express":    {"graphiql", "playground", "api-docs", "swagger.json"},
	"nginx":      {".env", "server-status", "server-info"},
	"apache":     {"server-status", "server-info", ".htaccess"},
	"tomcat":     {"manager/html", "host-manager/html", "WEB-INF/web.xml"},
	"jenkins":    {"script", "configure", "manage", "asynchPeople"},
	"gitlab":     {"api/v4/projects", "dashboard", "profile"},
	"bitbucket":  {"rest/api/latest", "dashboard"},
	"kubernetes": {"api", "apis", "healthz", "version"},
	"docker":     {"/v2/_catalog"},
	"mongodb":    {"/admin"},
	"postgres":   {"/pgadmin"},
	"redis":      {"/"},
	"graphql":    {"/graphql", "/graphiql", "/playground", "/altair"},
	"swagger":    {"/swagger", "/swagger-ui", "/api-docs", "/openapi.json"},
	"grpc":       {"/grpc.reflection", "/grpc.health.v1.Health/Check"},
}

// Industry vocabulary
var industryPaths = map[string][]string{
	"fintech":    {"transactions", "ledger", "wallet", "kyc", "compliance", "accounts", "transfers", "payments"},
	"healthcare": {"patients", "records", "appointments", "prescriptions", "lab-results"},
	"ecommerce":  {"products", "cart", "orders", "inventory", "coupons", "wishlist"},
	"saaS":       {"tenants", "organizations", "workspaces", "billing", "subscriptions", "usage"},
	"gaming":     {"leaderboard", "achievements", "inventory", "matches"},
	"education":  {"courses", "enrollments", "grades", "assignments"},
}

func (t *WordlistGenTool) Name() string {
	return "wordlist_gen"
}

func (t *WordlistGenTool) Run(ctx context.Context, scanCtx *recon.ScanContext, targets []string, threads int) ([]recon.Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, t.Name())
	if rateLimit <= 0 {
		rateLimit = 10
	}
	_ = rate.Limit(rateLimit)

	var allEvents []recon.Event

	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}

		domain := extractDomainFromTarget(target)
		if domain == "" {
			continue
		}

		wordlist := t.Generate(domain, nil, nil, "")

		// Save wordlist to file
		outputDir := filepath.Join(".", "wordlists", "generated")
		_ = os.MkdirAll(outputDir, 0700)
		outputPath := filepath.Join(outputDir, domain+".txt")

		if err := os.WriteFile(outputPath, []byte(strings.Join(wordlist, "\n")), 0600); err == nil {
			allEvents = append(allEvents, recon.NewEvent(target, t.Name(), "wordlist_generated", map[string]string{
				"domain":     domain,
				"path_count": fmt.Sprintf("%d", len(wordlist)),
				"output":     outputPath,
			}))
		}
	}

	return allEvents, nil
}

func (t *WordlistGenTool) Generate(targetDomain string, detectedTechs []string, discoveredPaths []string, industry string) []string {
	seen := make(map[string]struct{})
	var words []string

	addWord := func(w string) {
		w = strings.TrimSpace(w)
		if w == "" {
			return
		}
		if _, ok := seen[w]; ok {
			return
		}
		seen[w] = struct{}{}
		words = append(words, w)
	}

	// Company vocabulary
CompanyNameVocab(targetDomain, addWord)

	// Tech stack vocabulary
	for _, tech := range detectedTechs {
		techLower := strings.ToLower(tech)
		for keyword, paths := range techPaths {
			if strings.Contains(techLower, keyword) {
				for _, p := range paths {
					addWord(p)
				}
			}
		}
	}

	// Discovered path vocabulary: derive variations
	for _, path := range discoveredPaths {
		derivePathVariations(path, addWord)
	}

	// Industry vocabulary
	if industry != "" {
		industryLower := strings.ToLower(industry)
		for ind, paths := range industryPaths {
			if strings.Contains(industryLower, ind) {
				for _, p := range paths {
					addWord(p)
				}
			}
		}
	}

	// Common high-value paths always included
	commonPaths := []string{
		"admin", "login", "api", "dashboard", "health", "status",
		"config", "env", "debug", "trace", "metrics", "prometheus",
		"backup", "db", "database", "sql", "phpmyadmin", "adminer",
		".git", ".env", ".htaccess", "robots.txt", "sitemap.xml",
		"crossdomain.xml", "security.txt", "well-known/security.txt",
		"swagger", "api-docs", "graphql", "graphiql",
	}
	for _, p := range commonPaths {
		addWord(p)
	}

	sort.Strings(words)
	return words
}

func CompanyNameVocab(domain string, addWord func(string)) {
	parts := strings.Split(domain, ".")
	if len(parts) == 0 {
		return
	}

	// Main company name (first part)
	company := parts[0]
	addWord(company)
	addWord(company + "-api")
	addWord(company + "-admin")
	addWord(company + "-portal")
	addWord(company + "-internal")
	addWord(company + "-staging")
	addWord(company + "-dev")
	addWord(company + "-test")
	addWord(company + "-cdn")
	addWord(company + "-assets")
	addWord(company + "-static")
	addWord(company + "-media")
	addWord(company + "-files")
	addWord(company + "-backup")
	addWord(company + "-db")
	addWord(company + "-mail")
	addWord(company + "-smtp")
	addWord(company + "-vpn")
	addWord(company + "-auth")
	addWord(company + "-sso")
	addWord(company + "-status")
	addWord(company + "-health")

	// Hyphenated variations
	if len(company) > 3 {
		addWord(company[:3] + "-api")
		addWord(company[:3] + "-admin")
	}
}

func derivePathVariations(path string, addWord func(string)) {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return
	}

	// Add the base resource name
	addWord(parts[0])

	// Add common suffixes
	suffixes := []string{"", "/admin", "/settings", "/config", "/list", "/export", "/import", "/search", "/bulk", "/batch", "/status", "/health"}
	for _, suffix := range suffixes {
		addWord(parts[0] + suffix)
	}

	// If path has version, also try other versions
	if len(parts) > 1 && strings.HasPrefix(parts[0], "v") {
		base := strings.Join(parts[1:], "/")
		for _, ver := range []string{"v1", "v2", "v3"} {
			addWord(ver + "/" + base)
		}
	}

	// Add sibling paths
	if len(parts) > 1 {
		parent := parts[0]
		siblings := []string{"users", "admin", "settings", "profile", "accounts", "roles", "permissions", "logs", "audit"}
		for _, sib := range siblings {
			addWord(parent + "/" + sib)
		}
	}
}

func extractDomainFromTarget(target string) string {
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	target = strings.Split(target, "/")[0]
	target = strings.Split(target, ":")[0]
	return strings.ToLower(target)
}

var _ recon.Tool = (*WordlistGenTool)(nil)
