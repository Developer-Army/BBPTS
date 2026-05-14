package recon

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FingerprintRecord stores a fingerprint snapshot for a host at a point in time.
type FingerprintRecord struct {
	Host        string    `json:"host"`
	JARMHash    string    `json:"jarm_hash"`
	FaviconHash string    `json:"favicon_hash"`
	TLSIssuer   string    `json:"tls_issuer,omitempty"`
	TLSSubject  string    `json:"tls_subject,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	SessionID   string    `json:"session_id"`
	Checksum    string    `json:"checksum"` // for quick change detection
}

// FingerprintResult is the canonical result emitted by Fingerprinter.
type FingerprintResult = Result

// FingerprintChange describes a fingerprint transition detected for a host.
type FingerprintChange struct {
	Host          string            `json:"host"`
	Previous      FingerprintRecord `json:"previous"`
	Current       FingerprintRecord `json:"current"`
	ChangedFields []string          `json:"changed_fields"`
	DetectedAt    time.Time         `json:"detected_at"`
}

// FingerprintTimeline tracks fingerprint history per host to detect infrastructure changes.
type FingerprintTimeline struct {
	baseDir string
	mu      sync.RWMutex
	history map[string][]FingerprintRecord // host → records (desc by timestamp)
}

// NewFingerprintTimeline creates a timeline store.
func NewFingerprintTimeline(baseDir string) (*FingerprintTimeline, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create timeline dir: %w", err)
	}
	ft := &FingerprintTimeline{
		baseDir: baseDir,
		history: make(map[string][]FingerprintRecord),
	}
	// Load existing history from disk (best-effort)
	if err := ft.loadAllHistory(); err != nil {
		slog.Warn("Failed to load existing fingerprint timeline", "error", err)
	}
	return ft, nil
}

// Record saves a new fingerprint snapshot for a host.
func (ft *FingerprintTimeline) Record(sessionID string, result FingerprintResult) error {
	rec := FingerprintRecord{
		Host:        result.Host,
		JARMHash:    result.JARMHash,
		FaviconHash: result.FaviconHash,
		TLSIssuer:   result.TLSIssuer,
		TLSSubject:  result.TLSSubject,
		Timestamp:   time.Now().UTC(),
		SessionID:   sessionID,
	}
	rec.Checksum = ft.computeRecordChecksum(rec)

	ft.mu.Lock()
	defer ft.mu.Unlock()

	// Prepend to keep history sorted descending by timestamp
	ft.history[result.Host] = append([]FingerprintRecord{rec}, ft.history[result.Host]...)

	// Prune to last 30 entries per host (memory control)
	if len(ft.history[result.Host]) > 30 {
		ft.history[result.Host] = ft.history[result.Host][:30]
	}

	// Async persist
	go ft.persistRecord(result.Host, rec)

	return nil
}

// GetChanges returns hosts whose fingerprint changed within the given window.
func (ft *FingerprintTimeline) GetChanges(since time.Duration) map[string][]FingerprintChange {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	changes := make(map[string][]FingerprintChange)
	cutoff := time.Now().Add(-since)

	for host, records := range ft.history {
		if len(records) < 2 {
			continue
		}

		var latest, previous *FingerprintRecord
		for i, r := range records {
			if r.Timestamp.Before(cutoff) {
				// First record that is older than cutoff = previous
				if i > 0 {
					previous = &records[i-1]
					latest = &records[i-1] // latest within window
				}
				break
			}
			// r.Timestamp >= cutoff, r is within window
			if latest == nil {
				latest = &r
			}
		}
		if latest == nil || previous == nil {
			continue
		}

		if latest.JARMHash != previous.JARMHash ||
			latest.FaviconHash != previous.FaviconHash ||
			latest.TLSIssuer != previous.TLSIssuer ||
			latest.TLSSubject != previous.TLSSubject {

			chg := FingerprintChange{
				Host:          host,
				Previous:      *previous,
				Current:       *latest,
				ChangedFields: ft.diffFields(*previous, *latest),
				DetectedAt:    latest.Timestamp,
			}
			changes[host] = append(changes[host], chg)
		}
	}

	return changes
}

// diffFields returns a human-readable list of changed fields.
func (ft *FingerprintTimeline) diffFields(prev, curr FingerprintRecord) []string {
	var changed []string
	if curr.JARMHash != prev.JARMHash {
		changed = append(changed, fmt.Sprintf("JARM: %s→%s", safeHash(prev.JARMHash), safeHash(curr.JARMHash)))
	}
	if curr.FaviconHash != prev.FaviconHash {
		changed = append(changed, fmt.Sprintf("favicon: %s→%s", safeHash(prev.FaviconHash), safeHash(curr.FaviconHash)))
	}
	if curr.TLSIssuer != prev.TLSIssuer {
		changed = append(changed, fmt.Sprintf("TLS Issuer: %s→%s", prev.TLSIssuer, curr.TLSIssuer))
	}
	if curr.TLSSubject != prev.TLSSubject {
		changed = append(changed, fmt.Sprintf("TLS Subject: %s→%s", prev.TLSSubject, curr.TLSSubject))
	}
	return changed
}

func safeHash(h string) string {
	if len(h) < 8 {
		return h
	}
	return h[:8]
}

// GetHistory returns the fingerprint history for a host.
func (ft *FingerprintTimeline) GetHistory(host string, limit int) []FingerprintRecord {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	records, ok := ft.history[host]
	if !ok {
		return nil
	}
	if limit > 0 && limit < len(records) {
		return records[:limit]
	}
	return records
}

// ClusterByInfrastructure groups hosts that share identical latest fingerprints.
func (ft *FingerprintTimeline) ClusterByInfrastructure() map[string][]string {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	clusters := make(map[string][]string)

	for host, records := range ft.history {
		if len(records) == 0 {
			continue
		}
		latest := records[0]
		if latest.JARMHash == "" && latest.FaviconHash == "" {
			continue
		}
		key := fmt.Sprintf("jarm:%s|fav:%s", latest.JARMHash, latest.FaviconHash)
		clusters[key] = append(clusters[key], host)
	}
	return clusters
}

// computeRecordChecksum creates a hash of fingerprint fields.
func (ft *FingerprintTimeline) computeRecordChecksum(rec FingerprintRecord) string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s", rec.Host, rec.JARMHash, rec.FaviconHash, rec.TLSIssuer, rec.TLSSubject)
	h := sha256.Sum256([]byte(data))
	return hex.EncodeToString(h[:8])
}

// persistRecord writes a single record to JSONL file.
func (ft *FingerprintTimeline) persistRecord(host string, rec FingerprintRecord) {
	hostDir := filepath.Join(ft.baseDir, sanitizeHost(host))
	if err := os.MkdirAll(hostDir, 0700); err != nil {
		slog.Warn("Failed to create host dir", "host", host, "error", err)
		return
	}

	fpath := filepath.Join(hostDir, "fingerprints.jsonl")
	line, err := json.Marshal(rec)
	if err != nil {
		slog.Warn("Marshal failed", "error", err)
		return
	}

	f, err := os.OpenFile(fpath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		slog.Warn("Open failed", "path", fpath, "error", err)
		return
	}
	defer f.Close()
	f.Write(append(line, '\n'))
}

// loadAllHistory scans disk and loads all fingerprint history.
func (ft *FingerprintTimeline) loadAllHistory() error {
	ft.mu.Lock()
	defer ft.mu.Unlock()

	ft.history = make(map[string][]FingerprintRecord)

	return filepath.Walk(ft.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Base(path) == "fingerprints.jsonl" {
			host := filepath.Base(filepath.Dir(path))
			return ft.loadHostHistory(host)
		}
		return nil
	})
}

// loadHostHistory reads JSONL for a host.
func (ft *FingerprintTimeline) loadHostHistory(host string) error {
	hostDir := filepath.Join(ft.baseDir, sanitizeHost(host))
	fpath := filepath.Join(hostDir, "fingerprints.jsonl")

	data, err := os.ReadFile(fpath)
	if err != nil {
		return err
	}

	var records []FingerprintRecord
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var rec FingerprintRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		records = append(records, rec)
	}

	// Sort desc by timestamp
	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.After(records[j].Timestamp)
	})

	ft.history[host] = records
	return nil
}

// sanitizeHost returns hostname without port, lowercase.
func sanitizeHost(host string) string {
	for i, r := range host {
		if r == ':' || r == '/' {
			return strings.ToLower(host[:i])
		}
	}
	return strings.ToLower(host)
}
