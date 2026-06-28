package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/time/rate"
)

// IDORAssistTool identifies numeric/UUID parameters from crawled URLs,
// clusters them by likely object type, and generates a structured manual testing checklist.
type IDORAssistTool struct{}

func (i *IDORAssistTool) Name() string {
	return "idor_assist"
}

// paramPattern matches common ID-like values in URL parameters and path segments.
var (
	numericIDRe = regexp.MustCompile(`^\d{1,10}$`)
	uuidRe      = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	base64Re    = regexp.MustCompile(`^[A-Za-z0-9+/]{16,}={0,2}$`)
	hexIDRe     = regexp.MustCompile(`^[0-9a-f]{12,64}$`)
)

// objectTypeKeywords maps URL path segments to likely business object types.
var objectTypeKeywords = map[string]string{
	"user":        "user",
	"users":       "user",
	"profile":     "user",
	"account":     "user",
	"order":       "order",
	"orders":      "order",
	"invoice":     "order",
	"document":    "document",
	"documents":   "document",
	"file":        "document",
	"files":       "document",
	"report":      "document",
	"message":     "message",
	"messages":    "message",
	"chat":        "message",
	"comment":     "comment",
	"comments":    "comment",
	"review":      "comment",
	"payment":     "payment",
	"payments":    "payment",
	"transaction": "payment",
	"transfer":    "payment",
	"project":     "project",
	"workspace":   "project",
	"team":        "organization",
	"org":         "organization",
	"company":     "organization",
	"admin":       "admin",
	"settings":    "settings",
	"config":      "settings",
	"ticket":      "ticket",
	"issue":       "ticket",
	"task":        "ticket",
	"product":     "product",
	"item":        "product",
	"cart":        "cart",
	"session":     "session",
	"token":       "session",
	"api":         "api",
}

// riskByObjectType maps object types to risk levels.
var riskByObjectType = map[string]string{
	"user":         "high",
	"payment":      "critical",
	"order":        "high",
	"document":     "high",
	"message":      "high",
	"admin":        "critical",
	"settings":     "high",
	"session":      "critical",
	"organization": "medium",
	"project":      "medium",
	"ticket":       "medium",
	"comment":      "low",
	"product":      "low",
	"cart":         "medium",
	"api":          "medium",
}

// idorCluster represents a group of URLs sharing the same endpoint pattern and parameter.
type idorCluster struct {
	Pattern     string   // Normalized endpoint pattern, e.g. /api/users/{id}
	ParamName   string   // Parameter name carrying the ID
	ParamType   string   // numeric, uuid, base64, hex
	SampleIDs   []string // Sample ID values found
	ObjectType  string   // Inferred object type
	Risk        string   // Estimated risk level
	SampleURLs  []string // Original URLs in this cluster
	InPath      bool     // Whether the parameter is in the path vs query
}

func (i *IDORAssistTool) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	// Filter to HTTP URLs with parameters or path IDs
	var httpURLs []string
	for _, t := range targets {
		if strings.HasPrefix(strings.ToLower(t), "http://") || strings.HasPrefix(strings.ToLower(t), "https://") {
			httpURLs = append(httpURLs, t)
		}
	}
	if len(httpURLs) == 0 {
		return nil, nil
	}

	rateLimit := ToolRateLimitFromCtx(ctx, i.Name())
	_ = rate.Limit(rateLimit) // IDOR assist is purely analytical, no HTTP requests needed

	// Phase 1: Extract parameters and cluster by endpoint pattern
	clusters := i.extractAndCluster(httpURLs)
	if len(clusters) == 0 {
		return nil, nil
	}

	// Phase 2: Generate checklist events
	var events []Event

	for _, cluster := range clusters {
		if len(cluster.SampleIDs) == 0 {
			continue
		}

		// Build testing checklist
		checklist := i.buildChecklist(cluster)

		props := map[string]string{
			"type":          "idor_checklist",
			"pattern":       cluster.Pattern,
			"param_name":    cluster.ParamName,
			"param_type":    cluster.ParamType,
			"object_type":   cluster.ObjectType,
			"risk":          cluster.Risk,
			"sample_ids":    strings.Join(truncateSlice(cluster.SampleIDs, 10), ", "),
			"sample_count":  fmt.Sprintf("%d", len(cluster.SampleIDs)),
			"url_count":     fmt.Sprintf("%d", len(cluster.SampleURLs)),
			"checklist":     checklist,
			"description":   fmt.Sprintf("IDOR testing candidate: %s parameter '%s' in %s (%d unique IDs across %d URLs)", cluster.ParamType, cluster.ParamName, cluster.Pattern, len(cluster.SampleIDs), len(cluster.SampleURLs)),
		}

		events = append(events, NewEventWithSeverity(cluster.Pattern, i.Name(), "idor_checklist", props, cluster.Risk))
	}

	// Phase 3: Optional LLM enrichment if API key is available
	llmEvents := i.enrichWithLLM(ctx, clusters)
	events = append(events, llmEvents...)

	if len(events) > 0 {
		slog.Info("IDOR assistant analysis completed", "clusters", len(clusters), "checklist_items", len(events))
	}

	return events, nil
}

// extractAndCluster parses all URLs, finds ID-like parameters, and clusters them.
func (i *IDORAssistTool) extractAndCluster(urls []string) []idorCluster {
	type clusterKey struct {
		pattern   string
		paramName string
	}

	clusterMap := make(map[clusterKey]*idorCluster)

	for _, rawURL := range urls {
		parsed, err := url.Parse(rawURL)
		if err != nil || parsed.Host == "" {
			continue
		}

		// Check query parameters for IDs
		for param, values := range parsed.Query() {
			paramLower := strings.ToLower(param)
			if !isIDLikeParamName(paramLower) {
				continue
			}
			for _, val := range values {
				idType := classifyID(val)
				if idType == "" {
					continue
				}

				// Normalize pattern: scheme://host/path (without query)
				pattern := fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, normalizePath(parsed.Path))
				key := clusterKey{pattern: pattern, paramName: param}

				if _, ok := clusterMap[key]; !ok {
					objectType := inferObjectType(parsed.Path)
					clusterMap[key] = &idorCluster{
						Pattern:    pattern + "?" + param + "={id}",
						ParamName:  param,
						ParamType:  idType,
						ObjectType: objectType,
						Risk:       riskForObjectType(objectType),
						InPath:     false,
					}
				}

				c := clusterMap[key]
				if !containsStr(c.SampleIDs, val) && len(c.SampleIDs) < 50 {
					c.SampleIDs = append(c.SampleIDs, val)
				}
				if !containsStr(c.SampleURLs, rawURL) && len(c.SampleURLs) < 20 {
					c.SampleURLs = append(c.SampleURLs, rawURL)
				}
			}
		}

		// Check path segments for IDs
		pathSegments := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		for idx, segment := range pathSegments {
			idType := classifyID(segment)
			if idType == "" {
				continue
			}

			// Build pattern with {id} placeholder
			patternSegments := make([]string, len(pathSegments))
			copy(patternSegments, pathSegments)
			patternSegments[idx] = "{id}"
			pattern := fmt.Sprintf("%s://%s/%s", parsed.Scheme, parsed.Host, strings.Join(patternSegments, "/"))

			// Determine param name from preceding path segment
			paramName := "path_id"
			if idx > 0 {
				paramName = pathSegments[idx-1]
			}

			key := clusterKey{pattern: pattern, paramName: paramName}

			if _, ok := clusterMap[key]; !ok {
				objectType := inferObjectType(parsed.Path)
				clusterMap[key] = &idorCluster{
					Pattern:    pattern,
					ParamName:  paramName,
					ParamType:  idType,
					ObjectType: objectType,
					Risk:       riskForObjectType(objectType),
					InPath:     true,
				}
			}

			c := clusterMap[key]
			if !containsStr(c.SampleIDs, segment) && len(c.SampleIDs) < 50 {
				c.SampleIDs = append(c.SampleIDs, segment)
			}
			if !containsStr(c.SampleURLs, rawURL) && len(c.SampleURLs) < 20 {
				c.SampleURLs = append(c.SampleURLs, rawURL)
			}
		}
	}

	// Convert map to sorted slice
	clusters := make([]idorCluster, 0, len(clusterMap))
	for _, c := range clusterMap {
		if len(c.SampleIDs) >= 2 { // Only include clusters with 2+ distinct IDs
			clusters = append(clusters, *c)
		}
	}

	// Sort by risk (critical > high > medium > low) then by ID count
	riskOrder := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}
	sort.Slice(clusters, func(a, b int) bool {
		ra, rb := riskOrder[clusters[a].Risk], riskOrder[clusters[b].Risk]
		if ra != rb {
			return ra < rb
		}
		return len(clusters[a].SampleIDs) > len(clusters[b].SampleIDs)
	})

	return clusters
}

// buildChecklist generates a structured IDOR testing guide for a cluster.
func (i *IDORAssistTool) buildChecklist(c idorCluster) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf("## IDOR Test: %s\n\n", c.Pattern))
	b.WriteString(fmt.Sprintf("**Object Type:** %s | **Risk:** %s | **Param:** %s (%s)\n\n", c.ObjectType, strings.ToUpper(c.Risk), c.ParamName, c.ParamType))

	b.WriteString("### Sample IDs Found\n")
	for idx, id := range truncateSlice(c.SampleIDs, 10) {
		b.WriteString(fmt.Sprintf("  %d. `%s`\n", idx+1, id))
	}
	if len(c.SampleIDs) > 10 {
		b.WriteString(fmt.Sprintf("  ... and %d more\n", len(c.SampleIDs)-10))
	}

	b.WriteString("\n### Testing Steps\n")
	b.WriteString("1. **Authenticate as User A** — note the IDs returned for this user's resources\n")
	b.WriteString("2. **Authenticate as User B** — note different IDs for User B's resources\n")
	b.WriteString("3. **Cross-access test** — using User B's session, request User A's IDs:\n")

	if len(c.SampleURLs) > 0 {
		b.WriteString(fmt.Sprintf("   - `curl -H 'Cookie: session=USER_B' '%s'`\n", c.SampleURLs[0]))
	}

	switch c.ParamType {
	case "numeric":
		b.WriteString("4. **Sequential enumeration** — try incrementing/decrementing the numeric ID\n")
		if len(c.SampleIDs) >= 2 {
			b.WriteString(fmt.Sprintf("   - Range observed: %s to %s\n", c.SampleIDs[0], c.SampleIDs[len(c.SampleIDs)-1]))
		}
	case "uuid":
		b.WriteString("4. **UUID collection** — gather UUIDs from API responses and test cross-access\n")
	case "base64", "hex":
		b.WriteString("4. **Decode and analyze** — decode the ID to understand internal structure\n")
	}

	b.WriteString("5. **Authorization bypass** — remove auth headers and test unauthenticated access\n")
	b.WriteString("6. **HTTP method switching** — try GET/POST/PUT/DELETE with cross-user IDs\n")

	if c.ObjectType == "user" || c.ObjectType == "payment" || c.ObjectType == "admin" {
		b.WriteString("\n### ⚠️ HIGH VALUE TARGET\n")
		b.WriteString(fmt.Sprintf("This endpoint handles **%s** data — confirmed IDOR here is likely bounty-eligible.\n", c.ObjectType))
	}

	return b.String()
}

// enrichWithLLM optionally sends cluster data to LLM for richer context analysis.
func (i *IDORAssistTool) enrichWithLLM(ctx context.Context, clusters []idorCluster) []Event {
	provider, model, apiURL, apiKey := GetLLMConfig(ctx)
	if apiKey == "" || len(clusters) == 0 {
		return nil
	}

	// Only send top 10 clusters to avoid token limits
	if len(clusters) > 10 {
		clusters = clusters[:10]
	}

	var clusterSummaries []string
	for _, c := range clusters {
		clusterSummaries = append(clusterSummaries, fmt.Sprintf(
			"Pattern: %s, Param: %s (%s), Object: %s, IDs: %s",
			c.Pattern, c.ParamName, c.ParamType, c.ObjectType, strings.Join(truncateSlice(c.SampleIDs, 5), ", "),
		))
	}

	prompt := fmt.Sprintf(`You are a bug bounty expert analyzing IDOR (Insecure Direct Object Reference) candidates from crawled URLs.

Here are the clustered endpoint patterns with ID-like parameters:
%s

For each cluster, assess:
1. Likelihood of being a real IDOR vulnerability (0-100)
2. What sensitive data might be exposed
3. Recommended testing priority (critical, high, medium, low)
4. Any relationships between clusters that could indicate deeper access control flaws

Output as JSON array:
[{"pattern": "...", "idor_likelihood": 85, "data_exposure": "...", "priority": "high", "notes": "..."}]`, strings.Join(clusterSummaries, "\n"))

	rawText, err := CallLLM(ctx, prompt, provider, model, apiURL, apiKey)
	if err != nil {
		slog.Debug("IDOR LLM enrichment failed", "error", err)
		return nil
	}

	type llmIDORResult struct {
		Pattern        string `json:"pattern"`
		IDORLikelihood int    `json:"idor_likelihood"`
		DataExposure   string `json:"data_exposure"`
		Priority       string `json:"priority"`
		Notes          string `json:"notes"`
	}

	var results []llmIDORResult
	cleaned := CleanLLMJSON(rawText)
	if err := json.Unmarshal([]byte(cleaned), &results); err != nil {
		start := strings.Index(cleaned, "[")
		end := strings.LastIndex(cleaned, "]")
		if start != -1 && end != -1 && end > start {
			_ = json.Unmarshal([]byte(cleaned[start:end+1]), &results)
		}
	}

	var events []Event
	for _, r := range results {
		if r.IDORLikelihood < 50 {
			continue
		}
		events = append(events, NewEvent(r.Pattern, i.Name(), "discovery", map[string]string{
			"type":            "ai_idor_analysis",
			"idor_likelihood": fmt.Sprintf("%d", r.IDORLikelihood),
			"data_exposure":   r.DataExposure,
			"priority":        r.Priority,
			"notes":           r.Notes,
			"ai_analysis":     fmt.Sprintf("IDOR likelihood: %d%%, Data exposure: %s", r.IDORLikelihood, r.DataExposure),
		}))
	}

	return events
}

// --- Helper functions ---

func isIDLikeParamName(name string) bool {
	idNames := []string{
		"id", "uid", "user_id", "userid", "account_id", "accountid",
		"order_id", "orderid", "doc_id", "docid", "document_id",
		"file_id", "fileid", "project_id", "projectid",
		"item_id", "itemid", "ticket_id", "ticketid",
		"message_id", "messageid", "comment_id", "commentid",
		"invoice_id", "invoiceid", "payment_id", "paymentid",
		"session_id", "sessionid", "token", "ref",
		"uuid", "guid", "key", "num", "number",
	}
	for _, n := range idNames {
		if name == n {
			return true
		}
	}
	// Also match params ending with _id or Id
	if strings.HasSuffix(name, "_id") || strings.HasSuffix(name, "id") {
		return true
	}
	return false
}

func classifyID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return ""
	}
	if numericIDRe.MatchString(value) {
		return "numeric"
	}
	if uuidRe.MatchString(value) {
		return "uuid"
	}
	if base64Re.MatchString(value) && len(value) >= 20 {
		return "base64"
	}
	if hexIDRe.MatchString(value) {
		return "hex"
	}
	return ""
}

func inferObjectType(path string) string {
	pathLower := strings.ToLower(path)
	segments := strings.Split(strings.Trim(pathLower, "/"), "/")

	// Check segments from right to left, ignoring generic segments like "api"
	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		if seg == "api" {
			continue
		}
		if objType, ok := objectTypeKeywords[seg]; ok {
			return objType
		}
	}

	// Fallback: check if path contains any keywords (ignoring "api")
	for keyword, objType := range objectTypeKeywords {
		if keyword == "api" {
			continue
		}
		if strings.Contains(pathLower, keyword) {
			return objType
		}
	}

	return "unknown"
}

func riskForObjectType(objectType string) string {
	if risk, ok := riskByObjectType[objectType]; ok {
		return risk
	}
	return "medium"
}

func normalizePath(path string) string {
	// Remove trailing slash and query string artifacts
	path = strings.TrimRight(path, "/")
	if path == "" {
		path = "/"
	}
	return path
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func truncateSlice(s []string, max int) []string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

var _ Tool = (*IDORAssistTool)(nil)
