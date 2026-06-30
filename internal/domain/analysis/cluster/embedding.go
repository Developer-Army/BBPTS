package cluster

import (
	"log/slog"
	"math"
	"strings"
	"sync"

	"github.com/Developer-Army/BBPTS/internal/domain/recon"
)

type TFIDFClustering struct {
	documents []string       // corpus of endpoint paths
	vocab     map[string]int // term → index
	idf       map[string]float64
	mu        sync.RWMutex
}

func NewTFIDFClustering() *TFIDFClustering {
	return &TFIDFClustering{
		vocab: make(map[string]int),
		idf:   make(map[string]float64),
	}
}

func (c *TFIDFClustering) Fit(endpoints []recon.Event) {
	c.mu.Lock()
	defer c.mu.Unlock()

	documents := make([]string, 0, len(endpoints))
	for _, ev := range endpoints {
		path := ev.Target

		if idx := strings.Index(path, "?"); idx >= 0 {
			path = path[:idx]
		}
		path = strings.ToLower(path)

		tokens := tokenizePath(path)
		doc := strings.Join(tokens, " ")
		documents = append(documents, doc)
	}
	c.documents = documents

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

	i := 0
	for term := range vocab {
		vocab[term] = i
		i++
	}
	c.vocab = vocab

	idf := make(map[string]float64)
	N := float64(len(documents))
	for term := range vocab {
		docFreq := 0
		for _, doc := range documents {
			if strings.Contains(doc, term) {
				docFreq++
			}
		}
		idf[term] = math.Log((1+N)/(1+float64(docFreq))) + 1
	}
	c.idf = idf

	slog.Info("TF-IDF clusterer fitted", "documents", len(documents), "vocab_size", len(vocab))
}

func (c *TFIDFClustering) Vector(path string) []float64 {
	path = strings.ToLower(path)
	if idx := strings.Index(path, "?"); idx >= 0 {
		path = path[:idx]
	}
	tokens := tokenizePath(path)

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

func (c *TFIDFClustering) Cluster(endpoints []recon.Event, similarityThreshold float64) map[int][]recon.Event {
	if len(endpoints) == 0 {
		return nil
	}

	if len(c.vocab) == 0 {
		c.Fit(endpoints)
	}

	clusters := make(map[int][]recon.Event)
	clusterID := 0
	assigned := make(map[int]bool)

	for i := 0; i < len(endpoints); i++ {
		if assigned[i] {
			continue
		}

		cluster := []recon.Event{endpoints[i]}
		assigned[i] = true

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

func tokenizePath(path string) []string {

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

		seg = strings.ReplaceAll(seg, "-", " ")
		seg = strings.ReplaceAll(seg, "_", " ")
		seg = strings.ToLower(seg)

		seg = splitCamelCase(seg)

		words := strings.Fields(seg)
		tokens = append(tokens, words...)
	}
	return tokens
}

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

func ExtractKeywords(path string) []string {
	keywords := []string{}
	tokens := tokenizePath(path)

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
