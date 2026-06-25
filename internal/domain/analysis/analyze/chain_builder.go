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

		var openRedirectTitle, oauthTitle string
		var selfXSSTitle, csrfTitle string
		var ssrfTitle, internalPortTitle string

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
	}

	return chains
}
