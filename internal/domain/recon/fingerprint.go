// Package recon provides reconnaissance domain logic
package recon

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result holds the fingerprint data for a single host.
type Result struct {
	Host        string `json:"host"`
	JARMHash    string `json:"jarm_hash"`
	FaviconHash string `json:"favicon_hash"`
	FaviconURL  string `json:"favicon_url"`
	TLSIssuer   string `json:"tls_issuer,omitempty"`
	TLSSubject  string `json:"tls_subject,omitempty"`
}

// Fingerprinter performs JARM and favicon fingerprinting against a list of hosts.
type Fingerprinter struct {
	httpClient *http.Client
	timeout    time.Duration
}

// New creates a Fingerprinter with sensible defaults.
func New() *Fingerprinter {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // intentional for recon
		DialContext: (&net.Dialer{
			Timeout: 8 * time.Second,
		}).DialContext,
	}
	return &Fingerprinter{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   12 * time.Second,
		},
		timeout: 12 * time.Second,
	}
}

// FingerprintAll fingerprints a list of targets concurrently, respecting context cancellation.
func (f *Fingerprinter) FingerprintAll(ctx context.Context, targets []string, concurrency int) []Result {
	if concurrency <= 0 {
		concurrency = 10
	}

	type work struct {
		idx    int
		target string
	}

	jobs := make(chan work, len(targets))
	out := make(chan Result, len(targets))

	for i := 0; i < concurrency; i++ {
		go func() {
			for w := range jobs {
				result := f.Fingerprint(ctx, w.target)
				out <- result
			}
		}()
	}

	for i, t := range targets {
		jobs <- work{idx: i, target: t}
	}
	close(jobs)

	results := make([]Result, 0, len(targets))
	for range targets {
		results = append(results, <-out)
	}
	return results
}

// Fingerprint generates JARM and favicon hashes for a single target.
func (f *Fingerprinter) Fingerprint(ctx context.Context, target string) Result {
	result := Result{Host: target}

	// Normalise to https:// if no scheme present
	probeURL := target
	if !strings.Contains(probeURL, "://") {
		probeURL = "https://" + probeURL
	}

	// --- TLS Fingerprint ---
	host := strings.TrimPrefix(strings.TrimPrefix(probeURL, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	tlsHost := host
	if !strings.Contains(tlsHost, ":") {
		tlsHost += ":443"
	}

	result.JARMHash = f.jarmHash(ctx, tlsHost)

	// --- TLS Cert Info ---
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: f.timeout},
		"tcp",
		tlsHost,
		&tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	)
	if err == nil {
		defer conn.Close()
		if len(conn.ConnectionState().PeerCertificates) > 0 {
			cert := conn.ConnectionState().PeerCertificates[0]
			result.TLSIssuer = cert.Issuer.CommonName
			result.TLSSubject = cert.Subject.CommonName
		}
	}

	// --- Favicon Hash ---
	faviconURL := probeURL
	if !strings.HasSuffix(faviconURL, "/") {
		faviconURL += "/"
	}
	faviconURL += "favicon.ico"
	result.FaviconURL = faviconURL
	result.FaviconHash = f.faviconHash(ctx, faviconURL)

	slog.Debug("fingerprint complete",
		"host", target,
		"jarm", result.JARMHash[:min(8, len(result.JARMHash))],
		"favicon", result.FaviconHash,
	)

	return result
}

// jarmHash generates a simplified JARM-inspired hash by performing multiple
// TLS probes with different cipher/extension configurations.
// Note: This is a simplified implementation. For production-grade JARM, use
// the canonical Go JARM library (github.com/RumbleDiscovery/jarm-go).
func (f *Fingerprinter) jarmHash(ctx context.Context, hostPort string) string {
	// Probe with different TLS versions to generate a distinguishing signature
	versions := []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS10,
	}

	h := fnv.New64a()
	for _, ver := range versions {
		select {
		case <-ctx.Done():
			break
		default:
		}
		conf := &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec
			MinVersion:         ver,
			MaxVersion:         ver,
		}
		dialer := &net.Dialer{Timeout: 4 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", hostPort, conf)
		if err != nil {
			fmt.Fprintf(h, "err_%d", ver)
			continue
		}
		cs := conn.ConnectionState()
		fmt.Fprintf(h, "%d_%d_%v", ver, cs.CipherSuite, cs.NegotiatedProtocol)
		conn.Close()
	}

	raw := h.Sum(nil)
	return hex.EncodeToString(raw)
}

// faviconHash fetches a favicon and returns a hex-encoded FNV-64a hash of its content.
// This hash is used to cluster hosts running identical server stacks.
func (f *Fingerprinter) faviconHash(ctx context.Context, faviconURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, faviconURL, nil)
	if err != nil {
		return ""
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil || len(body) == 0 {
		return ""
	}

	h := fnv.New64a()
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// ClusterByJARM groups results by their JARM hash.
// Clusters with more than one member indicate infrastructure-linked hosts.
func ClusterByJARM(results []Result) map[string][]Result {
	clusters := make(map[string][]Result)
	for _, r := range results {
		if r.JARMHash == "" {
			continue
		}
		clusters[r.JARMHash] = append(clusters[r.JARMHash], r)
	}
	return clusters
}

// ClusterByFavicon groups results by favicon hash.
func ClusterByFavicon(results []Result) map[string][]Result {
	clusters := make(map[string][]Result)
	for _, r := range results {
		if r.FaviconHash == "" {
			continue
		}
		clusters[r.FaviconHash] = append(clusters[r.FaviconHash], r)
	}
	return clusters
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
