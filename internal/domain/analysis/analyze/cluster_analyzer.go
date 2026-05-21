package analyze

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/Developer-Army/BBPTS/internal/domain/analysis/cluster"
	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// extractClusterHost extracts a normalized hostname from a URL or host string.
func extractClusterHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if ip := net.ParseIP(raw); ip != nil {
		return strings.ToLower(ip.String())
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err == nil && parsed.Host != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}
	if strings.Contains(raw, ":") {
		if h, _, err := net.SplitHostPort(raw); err == nil {
			return strings.ToLower(h)
		}
	}
	parsed, _ := url.Parse("https://" + raw)
	if parsed != nil && parsed.Host != "" {
		return strings.ToLower(parsed.Hostname())
	}
	return strings.ToLower(raw)
}

// ClusterAnalyzer evaluates endpoint clusters for attack surface density and novelty.
type ClusterAnalyzer struct {
	clusterer *cluster.TFIDFClustering
	clusters  map[int][]recon.Event // computed per-host clusters
}

func NewClusterAnalyzer() *ClusterAnalyzer {
	return &ClusterAnalyzer{
		clusterer: cluster.NewTFIDFClustering(),
		clusters:  make(map[int][]recon.Event),
	}
}

// Analyze computes cluster-based features.
func (ca *ClusterAnalyzer) Analyze(ev recon.Event, insight *Insight) {
	// Deferred: clustering is run after all events collected, not per-event.
	// This analyzer is a placeholder for post-processing scoring boost.
}

// PostProcess runs after insights are built; boosts scores based on endpoint clusters.
func (ca *ClusterAnalyzer) PostProcess(insights []Insight, allEvents []recon.Event) {
	if len(allEvents) < 2 {
		return
	}

	// Filter to endpoint-like events (exclude subdomains, ports, headers)
	var endpointEvents []recon.Event
	for _, ev := range allEvents {
		if ev.Type == "api_endpoint" || ev.Type == "endpoint" ||
			ev.Type == "js_endpoint" || ev.Type == "semantic_endpoint" ||
			strings.Contains(ev.Target, "/api/") || strings.Contains(ev.Target, "/graphql") {
			endpointEvents = append(endpointEvents, ev)
		}
	}
	if len(endpointEvents) < 2 {
		return
	}

	// Compute clusters
	clusters := ca.clusterer.Cluster(endpointEvents, 0.6)
	ca.clusters = clusters

	// Map host → max cluster size
	hostClusterSize := make(map[string]int)
	for _, members := range clusters {
		size := len(members)
		for _, ev := range members {
			host := extractClusterHost(ev.Target)
			if host == "" {
				continue
			}
			if existing, ok := hostClusterSize[host]; !ok || size > existing {
				hostClusterSize[host] = size
			}
		}
	}

	// Apply boost to insights
	for i := range insights {
		host := insights[i].Host
		size := hostClusterSize[host]
		if size >= 5 {
			insights[i].Score += 12
			addTag(&insights[i], "endpoint-cluster")
			addReason(&insights[i], fmt.Sprintf("Dense endpoint cluster detected (%d related endpoints)", size))
		} else if size >= 3 {
			insights[i].Score += 6
		}
	}

	slog.Info("Cluster analysis complete", "total_clusters", len(clusters), "hosts_boosted", len(hostClusterSize))
}
