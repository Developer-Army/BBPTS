package analyze

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/infrastructure/storage"
)

// VulnerabilityChain represents a chain of compatible vulnerabilities.
type VulnerabilityChain struct {
	Target       string            `json:"target"`
	Findings     []string          `json:"findings"`
	CombinedCVSS float64           `json:"combined_cvss"`
	ChainType    string            `json:"chain_type"`
	Description  string            `json:"description"`
}

// FindVulnerabilityChains analyzes the target/finding/vulnerability graph to discover compatible chains.
func FindVulnerabilityChains(nodes []storage.AssetNode, edges []storage.AssetEdge) []VulnerabilityChain {
	nodeMap := make(map[string]storage.AssetNode)
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}

	// Group target vulnerabilities by target host/value
	targetVulns := make(map[string][]storage.AssetNode)
	for _, edge := range edges {
		if strings.ToLower(edge.Relation) == "is_vulnerable_to" || strings.ToLower(edge.Relation) == "has_finding" {
			targetNode, okT := nodeMap[edge.SourceID]
			vulnNode, okV := nodeMap[edge.TargetID]
			if okT && okV {
				targetVulns[targetNode.Value] = append(targetVulns[targetNode.Value], vulnNode)
			}
		}
	}

	var chains []VulnerabilityChain

	// Check chains for each target
	for target, vulns := range targetVulns {
		var hasOpenRedirect, hasOAuth bool
		var hasSelfXSS, hasCSRF bool
		var hasSSRF, hasInternalPort bool
		var hasSubdomainTakeover, hasCookieScope bool
		var hasXXE, hasPathTraversal, hasFileRead bool
		var hasCORSMisconfig bool

		var openRedirectTitle, oauthTitle string
		var selfXSSTitle, csrfTitle string
		var ssrfTitle, internalPortTitle string
		var takeoverTitle, cookieScopeTitle string
		var xxeTitle, pathTraversalTitle, fileReadTitle string
		var corsTitle string

		for _, v := range vulns {
			name := strings.ToLower(v.Value)
			var props map[string]interface{}
			_ = json.Unmarshal(v.Properties, &props)

			desc := ""
			if d, ok := props["description"]; ok {
				desc = strings.ToLower(fmt.Sprintf("%v", d))
			}
			title := ""
			if t, ok := props["title"]; ok {
				title = fmt.Sprintf("%v", t)
			}
			if title == "" {
				title = v.Value
			}

			// Open Redirect
			if strings.Contains(name, "open-redirect") || strings.Contains(name, "open_redirect") || strings.Contains(desc, "redirect") {
				hasOpenRedirect = true
				openRedirectTitle = title
			}
			// OAuth
			if strings.Contains(name, "oauth") || strings.Contains(desc, "oauth") {
				hasOAuth = true
				oauthTitle = title
			}
			// Self-XSS
			if (strings.Contains(name, "xss") || strings.Contains(desc, "xss")) && (strings.Contains(name, "self") || strings.Contains(desc, "self")) {
				hasSelfXSS = true
				selfXSSTitle = title
			}
			// CSRF
			if strings.Contains(name, "csrf") || strings.Contains(desc, "csrf") || strings.Contains(name, "xsrf") {
				hasCSRF = true
				csrfTitle = title
			}
			// SSRF
			if strings.Contains(name, "ssrf") || strings.Contains(desc, "ssrf") {
				hasSSRF = true
				ssrfTitle = title
			}
			// Internal Port / Service
			if strings.Contains(name, "port") || strings.Contains(name, "internal") || strings.Contains(desc, "internal") || strings.Contains(desc, "port") {
				hasInternalPort = true
				internalPortTitle = title
			}
			// Subdomain Takeover
			if strings.Contains(name, "subdomain") || strings.Contains(name, "takeover") {
				hasSubdomainTakeover = true
				takeoverTitle = title
			}
			// Cookie Scope Issues
			if strings.Contains(name, "cookie") || strings.Contains(desc, "cookie scope") || strings.Contains(desc, "domain scope") {
				hasCookieScope = true
				cookieScopeTitle = title
			}
			// XXE
			if strings.Contains(name, "xxe") || strings.Contains(desc, "xml external") || strings.Contains(desc, "xml entity") {
				hasXXE = true
				xxeTitle = title
			}
			// Path Traversal / LFI
			if strings.Contains(name, "path-traversal") || strings.Contains(name, "path_traversal") || strings.Contains(name, "lfi") || strings.Contains(desc, "path traversal") || strings.Contains(desc, "directory traversal") {
				hasPathTraversal = true
				pathTraversalTitle = title
			}
			// File Read
			if strings.Contains(name, "file-read") || strings.Contains(name, "file_read") || strings.Contains(name, "arbitrary file") || strings.Contains(desc, "file read") {
				hasFileRead = true
				fileReadTitle = title
			}
			// CORS Misconfiguration
			if strings.Contains(name, "cors") || strings.Contains(desc, "cors misconfiguration") || strings.Contains(desc, "access-control-allow") {
				hasCORSMisconfig = true
				corsTitle = title
			}
		}

		// 1. Open Redirect + OAuth = Account Takeover
		if hasOpenRedirect && hasOAuth {
			chains = append(chains, VulnerabilityChain{
				Target:       target,
				Findings:     []string{openRedirectTitle, oauthTitle},
				CombinedCVSS: 9.8,
				ChainType:    "Account Takeover via OAuth hijacking",
				Description:  "Chaining an Open Redirect with OAuth redirect_uri misconfiguration allows an attacker to leak authorization codes or tokens to an external server, resulting in complete Account Takeover.",
			})
		}

		// 2. Self-XSS + CSRF = Stored XSS / Session Takeover
		if hasSelfXSS && hasCSRF {
			chains = append(chains, VulnerabilityChain{
				Target:       target,
				Findings:     []string{selfXSSTitle, csrfTitle},
				CombinedCVSS: 8.2,
				ChainType:    "Stored XSS via CSRF",
				Description:  "Chaining a Self-XSS vulnerability with CSRF allows an attacker to force victim browsers to submit payloads that trigger Stored XSS, executing arbitrary JavaScript in the victim's session.",
			})
		}

		// 3. SSRF + Internal Port = RCE / Internal Network Pivot
		if hasSSRF && hasInternalPort {
			chains = append(chains, VulnerabilityChain{
				Target:       target,
				Findings:     []string{ssrfTitle, internalPortTitle},
				CombinedCVSS: 9.9,
				ChainType:    "Remote Code Execution (RCE) via SSRF",
				Description:  "Chaining Server-Side Request Forgery (SSRF) with internal port/service access (e.g. Docker API, Redis, K8s metadata) enables remote command execution or complete host compromise.",
			})
		}

		// 4. Subdomain Takeover + Cookie Scope = Cross-domain Session Theft
		if hasSubdomainTakeover && hasCookieScope {
			chains = append(chains, VulnerabilityChain{
				Target:       target,
				Findings:     []string{takeoverTitle, cookieScopeTitle},
				CombinedCVSS: 9.1,
				ChainType:    "Cross-domain Session Theft via Takeover + Cookie Scope",
				Description:  "A takeover-eligible subdomain with overly broad cookie scope allows an attacker who claims the subdomain to steal session cookies for the parent domain, leading to account takeover.",
			})
		}

		// 5. XXE + SSRF = Internal Network Exfiltration
		if hasXXE && hasSSRF {
			chains = append(chains, VulnerabilityChain{
				Target:       target,
				Findings:     []string{xxeTitle, ssrfTitle},
				CombinedCVSS: 9.4,
				ChainType:    "Internal Network Exfiltration via XXE + SSRF",
				Description:  "An XXE injection combined with SSRF allows an attacker to use the server as a proxy to scan and exfiltrate data from the internal network, reading files and accessing internal services.",
			})
		}

		// 6. CORS Misconfiguration + Auth Endpoint = Account Takeover
		if hasCORSMisconfig && hasOAuth {
			chains = append(chains, VulnerabilityChain{
				Target:       target,
				Findings:     []string{corsTitle, oauthTitle},
				CombinedCVSS: 8.8,
				ChainType:    "Account Takeover via CORS + Auth Endpoint",
				Description:  "A CORS misconfiguration (reflecting Origin with credentials) on an authentication endpoint allows a malicious page to read authenticated responses and steal tokens or session data.",
			})
		}

		// 7. Path Traversal + File Read = Sensitive File Disclosure
		if hasPathTraversal && hasFileRead {
			chains = append(chains, VulnerabilityChain{
				Target:       target,
				Findings:     []string{pathTraversalTitle, fileReadTitle},
				CombinedCVSS: 7.5,
				ChainType:    "Sensitive File Disclosure via Path Traversal",
				Description:  "Path traversal combined with arbitrary file read allows an attacker to read /etc/passwd, application secrets, private keys, and configuration files from the server.",
			})
		}
	}

	return chains
}
