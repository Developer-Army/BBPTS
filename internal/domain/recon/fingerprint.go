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

	"github.com/Developer-Army/BBPTS/internal/domain/security"
)

type Result struct {
	Host        string `json:"host"`
	JARMHash    string `json:"jarm_hash"`
	FaviconHash string `json:"favicon_hash"`
	FaviconURL  string `json:"favicon_url"`
	TLSIssuer   string `json:"tls_issuer,omitempty"`
	TLSSubject  string `json:"tls_subject,omitempty"`
}

type Fingerprinter struct {
	httpClient *http.Client
	timeout    time.Duration
}

func New() *Fingerprinter {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			pinnedAddr, _, err := security.ResolveAndValidateAddr(ctx, addr)
			if err != nil {
				return nil, err
			}
			dialer := &net.Dialer{Timeout: 8 * time.Second}
			return dialer.DialContext(ctx, network, pinnedAddr)
		},
	}
	transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		pinnedAddr, host, err := security.ResolveAndValidateAddr(ctx, addr)
		if err != nil {
			return nil, err
		}
		skipVerify := false
		if val := ctx.Value("insecure"); val != nil {
			if b, ok := val.(bool); ok {
				skipVerify = b
			}
		}
		dialer := &net.Dialer{Timeout: 8 * time.Second}
		return tls.DialWithDialer(dialer, network, pinnedAddr, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipVerify,
		})
	}
	return &Fingerprinter{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   12 * time.Second,
		},
		timeout: 12 * time.Second,
	}
}

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

func (f *Fingerprinter) Fingerprint(ctx context.Context, target string) Result {
	result := Result{Host: target}

	probeURL := target
	if !strings.Contains(probeURL, "://") {
		probeURL = "https://" + probeURL
	}

	host := strings.TrimPrefix(strings.TrimPrefix(probeURL, "https://"), "http://")
	host = strings.Split(host, "/")[0]
	tlsHost := host
	if !strings.Contains(tlsHost, ":") {
		tlsHost += ":443"
	}

	pinnedAddr, hostOnly, err := security.ResolveAndValidateAddr(ctx, tlsHost)
	if err != nil {
		slog.Warn("SSRF check blocked fingerprinting target", "target", target, "error", err)
		return result
	}

	result.JARMHash = f.jarmHash(ctx, pinnedAddr, hostOnly)

	skipVerify := false
	if val := ctx.Value("insecure"); val != nil {
		if b, ok := val.(bool); ok {
			skipVerify = b
		}
	}

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: f.timeout},
		"tcp",
		pinnedAddr,
		&tls.Config{
			ServerName:         hostOnly,
			InsecureSkipVerify: skipVerify,
		},
	)
	if err == nil {
		if len(conn.ConnectionState().PeerCertificates) > 0 {
			cert := conn.ConnectionState().PeerCertificates[0]
			result.TLSIssuer = cert.Issuer.CommonName
			result.TLSSubject = cert.Subject.CommonName
		}
		_ = conn.Close()
	}

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

func (f *Fingerprinter) jarmHash(ctx context.Context, pinnedAddr string, host string) string {

	versions := []uint16{
		tls.VersionTLS13,
		tls.VersionTLS12,
		tls.VersionTLS10,
	}

	h := fnv.New64a()
	for _, ver := range versions {
		select {
		case <-ctx.Done():
			return hex.EncodeToString(h.Sum(nil))
		default:
		}
		skipVerify := false
		if val := ctx.Value("insecure"); val != nil {
			if b, ok := val.(bool); ok {
				skipVerify = b
			}
		}
		conf := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: skipVerify,
			MinVersion:         ver,
			MaxVersion:         ver,
		}
		dialer := &net.Dialer{Timeout: 4 * time.Second}
		conn, err := tls.DialWithDialer(dialer, "tcp", pinnedAddr, conf)
		if err != nil {
			if _, err := fmt.Fprintf(h, "err_%d", ver); err != nil {
				return hex.EncodeToString(h.Sum(nil))
			}
			continue
		}
		cs := conn.ConnectionState()
		if _, err := fmt.Fprintf(h, "%d_%d_%v", ver, cs.CipherSuite, cs.NegotiatedProtocol); err != nil {
			_ = conn.Close()
			return hex.EncodeToString(h.Sum(nil))
		}
		_ = conn.Close()
	}

	raw := h.Sum(nil)
	return hex.EncodeToString(raw)
}

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
