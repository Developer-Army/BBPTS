package cluster

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// ComputeFingerprint generates a structural hash of an HTTP response body.
// It removes dynamic content (timestamps, CSRF tokens) to cluster similar pages.
func ComputeFingerprint(body string) string {
	// 1. Remove obvious dynamic content
	body = removeDynamicTokens(body)

	// 2. Strip text content to leave only HTML structure (tags and attributes)
	structure := extractHTMLStructure(body)

	// 3. Hash the structure
	h := fnv.New64a()
	h.Write([]byte(structure))
	return fmt.Sprintf("%x", h.Sum64())
}

func removeDynamicTokens(body string) string {
	// Remove CSRF tokens, UUIDs, cache-busters
	csrfRe := regexp.MustCompile(`(?i)(csrf|token|nonce)["']?\s*[:=]\s*["']?[a-zA-Z0-9_-]{16,}["']?`)
	body = csrfRe.ReplaceAllString(body, "TOKEN_REMOVED")

	uuidRe := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	body = uuidRe.ReplaceAllString(body, "UUID_REMOVED")

	return body
}

func extractHTMLStructure(body string) string {
	// Keep only <tags> and their class/id attributes for structural similarity
	tagRe := regexp.MustCompile(`<([a-zA-Z0-9]+)([^>]*)>`)
	matches := tagRe.FindAllStringSubmatch(body, -1)

	var structure strings.Builder
	for _, m := range matches {
		tag := strings.ToLower(m[1])
		structure.WriteString("<" + tag + ">")
	}

	return structure.String()
}

// ClusterByFingerprint groups events by their structural fingerprint.
func ClusterByFingerprint(events []recon.Event) map[string][]recon.Event {
	clusters := make(map[string][]recon.Event)

	for _, ev := range events {
		// Only cluster events that contain response bodies
		if body, ok := ev.Properties["response_body"]; ok {
			fp := ComputeFingerprint(body)
			ev.Properties["cluster_id"] = fp
			clusters[fp] = append(clusters[fp], ev)
		} else if tech, ok := ev.Properties["tech_stack"]; ok {
			// Cluster by tech stack if no body is available
			h := sha256.Sum256([]byte(tech))
			fp := fmt.Sprintf("tech_%x", h[:8])
			ev.Properties["cluster_id"] = fp
			clusters[fp] = append(clusters[fp], ev)
		} else {
			// Unclustered
			clusters["none"] = append(clusters["none"], ev)
		}
	}

	return clusters
}
