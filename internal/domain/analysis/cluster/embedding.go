package cluster

import (
	"log/slog"
	"math"
	"strings"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

// TFIDFClustering groups endpoints by semantic similarity using TF-IDF vectors.
// Lightweight, runs locally, no external dependencies.
type TFIDFClustering struct {
	documents []string       // corpus of endpoint paths
	vocab     map[string]int // term → index
	idf       map[string]float64
	mu        sync.RWMutex
}

// NewTFIDFClustering creates a new clusterer.
func NewTFIDFClustering() *TFIDFClustering {
	return &TFIDFClustering{
		vocab: make(map[string]int),
		idf:   make(map[string]float64),
	}
}

// Fit builds TF-IDF vocabulary from a set of endpoint paths.
func (c *TFIDFClustering) Fit(endpoints []recon.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Tokenize each endpoint path into terms (segments)
	documents := make([]string, 0, len(endpoints))
	for _, ev := range endpoints {
		path := ev.Target
		// Normalize: remove query, lower case
		if idx := strings.Index(path, "?"); idx >= 0 {
			path = path[:idx]
		}
		path = strings.ToLower(path)
		// Segment by '/' and keep non-empty tokens
		tokens := tokenizePath(path)
		doc := strings.Join(tokens, " ")
		documents = append(documents, doc)
	}
	c.documents = documents

	// Build vocabulary (all unique terms)
	vocab := make(map[string]int)
	for _, doc := range documents {
		terms := strings.Fields(doc)
		seen := make(map[string]struct{})
		for _, term := range terms {
			if _, ok := seen[term]; !ok {
				vocab[term] = 0
				seen[term] = struct{}{}
			}
		}
	}
	// Assign indices
	i := 0
	for term := range vocab {
		vocab[term] = i
		i++
	}
	c.vocab = vocab

	// Compute IDF (inverse document frequency)
	idf := make(map[string]float64)
	N := float64(len(documents))
	for term := range vocab {
		docFreq := 0
		for _, doc := range documents {
			if strings.Contains(doc, term) {
				docFreq++
			}
		}
		idf[term] = math.Log((1+N)/(1+float64(docFreq))) + 1 // smoothed IDF
	}
	c.idf = idf

	slog.Info("TF-IDF clusterer fitted", "documents", len(documents), "vocab_size", len(vocab))
}

// Vector returns the TF-IDF vector for a single endpoint path.
func (c *TFIDFClustering) Vector(path string) []float64 {
	path = strings.ToLower(path)
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	tokens := tokenizePath(path)

	// Term frequency (raw count)
	tf := make(map[string]float64)
	for _, term := range tokens {
		tf[term]++
	}
	// Normalize by max frequency (L1 norm)
	var maxFreq float64
	for _, f := range tf {
		if f > maxFreq {
			maxFreq = f
		}
	}
	if maxFreq > 0 {
		for term := range tf {
			tf[term] /= maxFreq
		}
	}

	// Build vector (same dimension as vocab)
	vec := make([]float64, len(c.vocab))
	c.mu.RLock()
	defer c.mu.RUnlock()
	for term, freq := range tf {
		if idx, ok := c.vocab[term]; ok {
			vec[idx] = freq * c.idf[term]
		}
	}
	return vec
}

// CosineSimilarity computes cosine similarity between two vectors.
func CosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// Cluster groups endpoints into clusters using DBSCAN-like density-based approach.
// Returns: clusterID → []endpoint events
func (c *TFIDFClustering) Cluster(endpoints []recon.Event, similarityThreshold float64) map[int][]recon.Event {
	if len(endpoints) == 0 {
		return nil
	}

	// Ensure fitted
	if len(c.vocab) == 0 {
		c.Fit(endpoints)
	}

	clusters := make(map[int][]recon.Event)
	clusterID := 0
	assigned := make(map[int]bool) // endpoint index → assigned cluster

	for i := 0; i < len(endpoints); i++ {
		if assigned[i] {
			continue
		}
		// Start new cluster
		cluster := []recon.Event{endpoints[i]}
		assigned[i] = true

		// Find neighbors
		for j := i + 1; j < len(endpoints); j++ {
			if assigned[j] {
				continue
			}
			vecI := c.Vector(endpoints[i].Target)
			vecJ := c.Vector(endpoints[j].Target)
			sim := CosineSimilarity(vecI, vecJ)
			if sim >= similarityThreshold {
				cluster = append(cluster, endpoints[j])
				assigned[j] = true
			}
		}

		clusters[clusterID] = cluster
		clusterID++
	}

	slog.Info("Endpoint clustering complete", "clusters", len(clusters), "total_endpoints", len(endpoints))
	return clusters
}

// tokenizePath splits a URL path into meaningful tokens.
func tokenizePath(path string) []string {
	// Remove leading/trailing slashes
	path = strings.Trim(path, "/")
	if path == "" {
		return []string{"root"}
	}

	segments := strings.Split(path, "/")
	tokens := make([]string, 0, len(segments))

	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		// further split on hyphens/underscores/camelCase?
		seg = strings.ReplaceAll(seg, "-", " ")
		seg = strings.ReplaceAll(seg, "_", " ")
		seg = strings.ToLower(seg)
		// Split camelCase (basic)
		seg = splitCamelCase(seg)

		words := strings.Fields(seg)
		tokens = append(tokens, words...)
	}
	return tokens
}

// splitCamelCase separates camelCase into tokens.
func splitCamelCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			result.WriteRune(' ')
		}
		result.WriteRune(r)
	}
	return result.String()
}

// --- Keyword extraction for high-value endpoint detection ---

// ExtractKeywords pulls significant keywords from a path.
func ExtractKeywords(path string) []string {
	keywords := []string{}
	tokens := tokenizePath(path)

	// Prioritize high-value terms
	highValue := map[string]bool{
		"admin": true, "api": true, "graphql": true, "auth": true, "login": true,
		"logout": true, "user": true, "account": true, "payment": true,
		"config": true, "secret": true, "internal": true, "debug": true,
		"test": true, "staging": true, "dev": true, "upload": true,
		"download": true, "export": true, "setting": true,
	}

	for _, token := range tokens {
		if highValue[token] {
			keywords = append(keywords, token)
		}
	}
	return keywords
}
