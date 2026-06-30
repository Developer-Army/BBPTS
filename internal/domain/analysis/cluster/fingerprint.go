package cluster

import (
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"regexp"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

func ComputeFingerprint(body string) string {

	body = removeDynamicTokens(body)

	structure := extractHTMLStructure(body)

	h := fnv.New64a()
	h.Write([]byte(structure))
	return fmt.Sprintf("%x", h.Sum64())
}

func removeDynamicTokens(body string) string {

	csrfRe := regexp.MustCompile(`(?i)(csrf|token|nonce)["']?\s*[:=]\s*["']?[a-zA-Z0-9_-]{16,}["']?`)
	body = csrfRe.ReplaceAllString(body, "TOKEN_REMOVED")

	uuidRe := regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	body = uuidRe.ReplaceAllString(body, "UUID_REMOVED")

	return body
}

func extractHTMLStructure(body string) string {

	tagRe := regexp.MustCompile(`<([a-zA-Z0-9]+)([^>]*)>`)
	matches := tagRe.FindAllStringSubmatch(body, -1)

	var structure strings.Builder
	for _, m := range matches {
		tag := strings.ToLower(m[1])
		structure.WriteString("<")
		structure.WriteString(tag)
		structure.WriteString(">")
	}

	return structure.String()
}

func ClusterByFingerprint(events []recon.Event) map[string][]recon.Event {
	clusters := make(map[string][]recon.Event)

	for _, ev := range events {

		if body, ok := ev.Properties["response_body"]; ok {
			fp := ComputeFingerprint(body)
			ev.Properties["cluster_id"] = fp
			clusters[fp] = append(clusters[fp], ev)
		} else if tech, ok := ev.Properties["tech_stack"]; ok {

			h := sha256.Sum256([]byte(tech))
			fp := fmt.Sprintf("tech_%x", h[:8])
			ev.Properties["cluster_id"] = fp
			clusters[fp] = append(clusters[fp], ev)
		} else {

			clusters["none"] = append(clusters["none"], ev)
		}
	}

	return clusters
}
