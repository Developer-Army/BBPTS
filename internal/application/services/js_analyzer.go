package services

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/network"
	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
	"golang.org/x/time/rate"
)

// JSAnalyzer parses JavaScript files to recover routing, mutations, and internal APIs.
type JSAnalyzer struct{}

func (j *JSAnalyzer) Name() string {
	return "js_analyzer"
}

func (j *JSAnalyzer) Run(ctx context.Context, targets []string, threads int) ([]Event, error) {
	if len(targets) == 0 {
		return nil, nil
	}

	var jsTargets []string
	for _, t := range targets {
		if strings.HasSuffix(t, ".js") || strings.Contains(t, ".js?") {
			jsTargets = append(jsTargets, t)
		}
	}
	if len(jsTargets) == 0 {
		return nil, nil
	}

	proxies := GetProxies(ctx)
	proxy := ""
	if len(proxies) > 0 {
		proxy = proxies[len(proxies)-1]
	}
	profile := network.BrowserProfile{
		Name:      "Default",
		UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	// We can use random or fallback for proxy
	_ = proxy
	client, _ := network.NewStealthClient(profile, "")
	if len(proxies) > 0 {
		// Rebuild client with proxy
		client, _ = network.NewStealthClient(profile, proxies[0])
	}
	if client != nil {
		client.SetCustomHeaders(HeadersFromCtx(ctx))
	}

	rateLimit := ToolRateLimitFromCtx(ctx, j.Name())
	pool := NewWorkerPool(threads, rate.Limit(rateLimit))

	return pool.Process(ctx, jsTargets, func(ctx context.Context, url string) ([]Event, error) {
		events := j.analyzeJS(ctx, client, url)
		return events, nil
	})
}

func (j *JSAnalyzer) analyzeJS(ctx context.Context, client *network.StealthClient, url string) []Event {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("failed to fetch JS", "url", url, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	content := string(bodyBytes)

	var events []Event

	// 1. GraphQL operation names (regex fallback)
	gqlRe := regexp.MustCompile(`(?i)(mutation|query)\s+([a-zA-Z0-9_]+)\s*[{(]`)
	gqlOps := gqlRe.FindAllStringSubmatch(content, -1)
	for _, match := range gqlOps {
		events = append(events, NewEvent(match[2], j.Name(), "graphql_operation", map[string]string{
			"source":  url,
			"op_type": match[1],
		}))
	}

	// 2. Delegate to domain JSAnalyzer
	domainAnalyzer := recon.NewJSAnalyzer()
	domainAnalyzer.SetHTTPClient(client)
	findings := domainAnalyzer.AnalyzeContent(url, content)

	// --- Differential JS Change Detection ---
	store := storage.FromContext(ctx)
	if store != nil {
		h := sha256.New()
		h.Write(bodyBytes)
		currentHash := fmt.Sprintf("%x", h.Sum(nil))

		prevEv, err := store.GetEvidenceModel(url)
		if err == nil && prevEv != nil && prevEv.Hash != currentHash {
			oldFindings := domainAnalyzer.AnalyzeContent(url, string(prevEv.RawData))
			diffText := diffFindings(oldFindings, findings)
			if diffText != "" {
				events = append(events, NewEventWithSeverity(url, j.Name(), "vulnerability", map[string]string{
					"vuln_name":   "JavaScript File Changed (New Attack Surface)",
					"severity":    "high",
					"evidence":    diffText,
					"description": "JS file content changed since last crawl. Diff:\n" + diffText,
				}, "high"))
				slog.Warn("JS file changed with new attack surface", "url", url)
			}
		}
		_ = store.SaveEvidence(url, extractHost(url), j.Name(), 1.0, bodyBytes, currentHash)
	}

	for _, f := range findings {
		switch f.Type {
		case "secret", "entropy":
			severity := f.Severity
			if severity == "" {
				severity = "high"
			}
			vulnName := "Exposed " + f.Name
			nameLower := strings.ToLower(f.Name)
			if strings.Contains(nameLower, "aws") {
				vulnName += " (aws_key)"
			} else if strings.Contains(nameLower, "slack") {
				vulnName += " (slack_token)"
			} else if strings.Contains(nameLower, "google") {
				vulnName += " (google_api)"
			} else if strings.Contains(nameLower, "github") {
				vulnName += " (github_token)"
			} else if strings.Contains(nameLower, "stripe") {
				vulnName += " (stripe_key)"
			}
			events = append(events, NewEvent(url, j.Name(), "vulnerability", map[string]string{
				"severity":  severity,
				"vuln_name": vulnName,
				"evidence":  "Found secret match: " + f.Value,
			}))
		case "endpoint", "semantic_endpoint":
			props := map[string]string{
				"source": url,
			}
			idx := strings.Index(content, f.Value)
			if idx != -1 {
				start := idx - 200
				if start < 0 {
					start = 0
				}
				end := idx + 200
				if end > len(content) {
					end = len(content)
				}
				window := content[start:end]
				if strings.Contains(strings.ToLower(window), "jwt") || strings.Contains(strings.ToLower(window), "bearer") || strings.Contains(strings.ToLower(window), "admin") {
					props["context"] = "auth_required or admin_context"
				}
			}
			events = append(events, NewEvent(f.Value, j.Name(), "api_endpoint", props))

			// Also emit a frontend_route if AST router definition
			if f.Type == "semantic_endpoint" && strings.Contains(f.Name, "Route:") {
				events = append(events, NewEvent(f.Value, j.Name(), "frontend_route", map[string]string{
					"source": url,
					"type":   "router_recovery",
				}))
			}
		case "framework", "lazy_route", "sourcemap":
			events = append(events, NewEvent(url, j.Name(), "discovery", map[string]string{
				"source": url,
				"detail": f.Name + ": " + f.Value,
				"type":   f.Type,
			}))
		}
	}

	// AI-powered semantic JS analysis (runs if LLM key is available)
	aiEvents := j.analyzeJSWithLLM(ctx, url, content)
	events = append(events, aiEvents...)

	return events
}

// jsAIFinding represents a single finding from the LLM JS analysis.
type jsAIFinding struct {
	Type        string `json:"type"`        // endpoint, parameter, auth_logic, hardcoded_value, security_op
	Value       string `json:"value"`       // The actual finding (URL, key, etc.)
	Description string `json:"description"` // Explanation of why it's interesting
	Severity    string `json:"severity"`    // info, low, medium, high
}

// analyzeJSWithLLM sends beautified JS chunks to an LLM for semantic analysis.
func (j *JSAnalyzer) analyzeJSWithLLM(ctx context.Context, sourceURL, content string) []Event {
	provider, model, apiURL, apiKey := GetLLMConfig(ctx)
	if apiKey == "" {
		return nil // No LLM key configured, skip gracefully
	}

	beautified := beautifyJS(content)
	chunks := chunkContent(beautified, 4000)
	if len(chunks) == 0 {
		return nil
	}

	// Limit to first 5 chunks to avoid token exhaustion
	if len(chunks) > 5 {
		chunks = chunks[:5]
	}

	var events []Event
	for i, chunk := range chunks {
		prompt := fmt.Sprintf(`You are a security researcher analyzing JavaScript source code from %s (chunk %d/%d).

Analyze this JavaScript code and identify:
1. API endpoints and URLs (internal APIs, external services)
2. Request parameters and their purposes
3. Authentication/authorization logic (token handling, session management, role checks)
4. Hardcoded values (API keys, tokens, secrets, credentials, internal IPs/hostnames)
5. Security-sensitive operations (eval, innerHTML, postMessage, crypto operations, file uploads)

JavaScript Code:
%s

Output your findings as a JSON array. Each finding must have:
- "type": one of "endpoint", "parameter", "auth_logic", "hardcoded_value", "security_op"
- "value": the actual code/string found
- "description": brief explanation of security relevance
- "severity": "info", "low", "medium", or "high"

If no findings, return an empty array [].
Output ONLY valid JSON, no markdown.`, sourceURL, i+1, len(chunks), chunk)

		rawText, err := CallLLM(ctx, prompt, provider, model, apiURL, apiKey)
		if err != nil {
			slog.Debug("AI JS analysis failed for chunk", "url", sourceURL, "chunk", i, "error", err)
			continue
		}

		var findings []jsAIFinding
		cleaned := CleanLLMJSON(rawText)
		if err := json.Unmarshal([]byte(cleaned), &findings); err != nil {
			// Try extracting JSON array
			start := strings.Index(cleaned, "[")
			end := strings.LastIndex(cleaned, "]")
			if start != -1 && end != -1 && end > start {
				_ = json.Unmarshal([]byte(cleaned[start:end+1]), &findings)
			}
		}

		for _, f := range findings {
			if f.Value == "" {
				continue
			}
			switch f.Type {
			case "endpoint":
				events = append(events, NewEvent(f.Value, j.Name(), "api_endpoint", map[string]string{
					"source":      sourceURL,
					"ai_analysis": f.Description,
					"method":      "llm_semantic",
				}))
			case "hardcoded_value":
				severity := f.Severity
				if severity == "" {
					severity = "medium"
				}
				events = append(events, NewEventWithSeverity(sourceURL, j.Name(), "vulnerability", map[string]string{
					"vuln_name":   "AI-Detected Hardcoded Value in JavaScript",
					"severity":    severity,
					"evidence":    f.Value,
					"description": f.Description,
				}, severity))
			case "auth_logic":
				events = append(events, NewEvent(sourceURL, j.Name(), "discovery", map[string]string{
					"source":      sourceURL,
					"type":        "auth_logic",
					"detail":      f.Value,
					"ai_analysis": f.Description,
				}))
			case "security_op":
				severity := f.Severity
				if severity == "" {
					severity = "low"
				}
				events = append(events, NewEventWithSeverity(sourceURL, j.Name(), "vulnerability", map[string]string{
					"vuln_name":   "AI-Detected Security-Sensitive JS Operation",
					"severity":    severity,
					"evidence":    f.Value,
					"description": f.Description,
				}, severity))
			case "parameter":
				events = append(events, NewEvent(f.Value, j.Name(), "discovery", map[string]string{
					"source":      sourceURL,
					"type":        "js_parameter",
					"ai_analysis": f.Description,
				}))
			}
		}
	}

	if len(events) > 0 {
		slog.Info("AI JS analysis completed", "url", sourceURL, "findings", len(events))
	}
	return events
}

// beautifyJS applies simple formatting to minified JS for better LLM comprehension.
func beautifyJS(content string) string {
	var b strings.Builder
	b.Grow(len(content) + len(content)/10)

	indent := 0
	for i := 0; i < len(content); i++ {
		c := content[i]
		switch c {
		case '{':
			b.WriteByte(c)
			b.WriteByte('\n')
			indent++
			writeIndent(&b, indent)
		case '}':
			b.WriteByte('\n')
			if indent > 0 {
				indent--
			}
			writeIndent(&b, indent)
			b.WriteByte(c)
		case ';':
			b.WriteByte(c)
			b.WriteByte('\n')
			writeIndent(&b, indent)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func writeIndent(b *strings.Builder, level int) {
	for i := 0; i < level; i++ {
		b.WriteString("  ")
	}
}

// chunkContent splits content into overlapping chunks for LLM processing.
func chunkContent(content string, chunkSize int) []string {
	if len(content) <= chunkSize {
		if len(content) == 0 {
			return nil
		}
		return []string{content}
	}

	overlap := chunkSize / 10 // 10% overlap
	var chunks []string
	for i := 0; i < len(content); {
		end := i + chunkSize
		if end > len(content) {
			end = len(content)
		}
		chunks = append(chunks, content[i:end])
		i = end - overlap
		if i >= len(content) {
			break
		}
	}
	return chunks
}

func diffFindings(oldFindings, newFindings []recon.JSFinding) string {
	oldMap := make(map[string]bool)
	for _, f := range oldFindings {
		key := f.Type + ":" + f.Value
		oldMap[key] = true
	}

	var newEndpoints []string
	var newSecrets []string

	for _, f := range newFindings {
		key := f.Type + ":" + f.Value
		if !oldMap[key] {
			switch f.Type {
			case "endpoint", "semantic_endpoint":
				newEndpoints = append(newEndpoints, f.Value)
			case "secret", "entropy":
				newSecrets = append(newSecrets, fmt.Sprintf("%s (%s)", f.Name, f.Value))
			}
		}
	}

	var parts []string
	if len(newEndpoints) > 0 {
		parts = append(parts, "New Endpoints:\n- " + strings.Join(newEndpoints, "\n- "))
	}
	if len(newSecrets) > 0 {
		parts = append(parts, "New Secrets:\n- " + strings.Join(newSecrets, "\n- "))
	}

	return strings.Join(parts, "\n\n")
}
