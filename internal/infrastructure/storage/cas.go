package storage

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// CAS (Content-Addressable Storage) manages deduplicated storage of recon artifacts
// like HTTP response bodies, JS files, and large JSON blobs.
type CAS struct {
	baseDir string
	mu      sync.RWMutex         // protects concurrent Store/Retrieve
	index   map[string]time.Time // hash → last accessed (for LRU eviction)
	maxSize int64                // optional quota in bytes (0 = unlimited)
}

// objectPath computes the full sharded path for a hash.
func (c *CAS) objectPath(hashStr string) string {
	if len(hashStr) < 4 {
		return filepath.Join(c.baseDir, hashStr)
	}
	shardDir := filepath.Join(c.baseDir, hashStr[:2], hashStr[2:4])
	return filepath.Join(shardDir, hashStr)
}

// CASOption configures CAS behavior.
type CASOption func(*CAS)

// WithMaxSize sets a storage quota. When exceeded, oldest files are evicted.
func WithMaxSize(bytes int64) CASOption {
	return func(c *CAS) {
		c.maxSize = bytes
	}
}

// NewCAS initializes a new content-addressable storage on disk.
// In a real distributed deployment, this could wrap an S3 bucket.
func NewCAS(baseDir string, opts ...CASOption) (*CAS, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create CAS directory: %w", err)
	}

	c := &CAS{
		baseDir: baseDir,
		index:   make(map[string]time.Time),
	}

	for _, opt := range opts {
		opt(c)
	}

	// Load existing index from disk (scan baseDir)
	if err := c.scanIndex(); err != nil {
		slog.Warn("CAS scan failed, starting fresh", "error", err)
	}

	return c, nil
}

// Store compresses and saves content to disk based on its SHA256 hash.
// It returns the hash (address) of the content.
func (c *CAS) Store(content []byte) (string, error) {
	if len(content) == 0 {
		return "", nil
	}

	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	shardDir := filepath.Join(c.baseDir, hashStr[:2], hashStr[2:4])
	if err := os.MkdirAll(shardDir, 0700); err != nil {
		return "", err
	}

	objectPath := filepath.Join(shardDir, hashStr)

	// If it already exists, just update access time and return hash (dedup hit)
	c.mu.RLock()
	if _, exists := c.index[hashStr]; exists {
		// Update access time (touch)
		if err := os.Chtimes(objectPath, time.Now(), time.Now()); err == nil {
			c.index[hashStr] = time.Now()
		}
		c.mu.RUnlock()
		return hashStr, nil
	}
	c.mu.RUnlock()

	// Compress and write
	file, err := os.Create(objectPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	gz := gzip.NewWriter(file)
	if _, err := gz.Write(content); err != nil {
		return "", err
	}
	if err := gz.Close(); err != nil {
		return "", err
	}

	// Update index and evict if needed
	c.mu.Lock()
	c.index[hashStr] = time.Now()
	if c.maxSize > 0 {
		c.evictIfNeeded()
	}
	c.mu.Unlock()

	return hashStr, nil
}

// evictIfNeeded deletes oldest entries until total size is under quota.
func (c *CAS) evictIfNeeded() {
	// Compute current total size
	var currentSize int64
	for hashStr := range c.index {
		path := c.objectPath(hashStr)
		if info, err := os.Stat(path); err == nil {
			currentSize += info.Size()
		}
	}

	// If under quota, nothing to do
	if currentSize <= c.maxSize {
		return
	}

	// Sort hashes by access time (oldest first) for eviction
	type entry struct {
		hash  string
		atime time.Time
		path  string
		size  int64
	}
	var entries []entry
	for hashStr, atime := range c.index {
		path := c.objectPath(hashStr)
		var size int64
		if info, err := os.Stat(path); err == nil {
			size = info.Size()
		}
		entries = append(entries, entry{hash: hashStr, atime: atime, path: path, size: size})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].atime.Before(entries[j].atime)
	})

	// Evict oldest until under quota
	var freed int64
	for _, e := range entries {
		if currentSize <= c.maxSize {
			break
		}
		if err := os.Remove(e.path); err == nil {
			delete(c.index, e.hash)
			currentSize -= e.size
			freed += e.size
			slog.Debug("CAS evicted old artifact", "hash", e.hash[:8], "freed_bytes", e.size)
		}
	}
}

// Retrieve fetches and decompresses an artifact by its hash.
func (c *CAS) Retrieve(hashStr string) ([]byte, error) {
	if len(hashStr) < 4 {
		return nil, fmt.Errorf("invalid hash")
	}

	// Fast path: check index first
	c.mu.RLock()
	_, exists := c.index[hashStr]
	c.mu.RUnlock()
	if !exists {
		return nil, fmt.Errorf("artifact not found in index: %s", hashStr[:8])
	}

	path := c.objectPath(hashStr)

	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Index out of sync with disk; remove stale entry
			c.mu.Lock()
			delete(c.index, hashStr)
			c.mu.Unlock()
		}
		return nil, fmt.Errorf("artifact not found: %w", err)
	}
	defer file.Close()

	gz, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}
	defer gz.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, gz); err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	// Update access time in index
	c.mu.Lock()
	c.index[hashStr] = time.Now()
	c.mu.Unlock()

	return buf.Bytes(), nil
}

// Exists checks if a hash exists in CAS without loading content.
func (c *CAS) Exists(hashStr string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.objectPath(hashStr)
	_, err := os.Stat(path)
	return err == nil
}

// Delete removes an object from CAS (used for TTL eviction).
func (c *CAS) Delete(hashStr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.objectPath(hashStr)
	return os.Remove(path)
}

// Stats returns storage statistics.
func (c *CAS) Stats() (count int, totalSize int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var size int64
	for hashStr := range c.index {
		path := c.objectPath(hashStr)
		if info, err := os.Stat(path); err == nil {
			count++
			size += info.Size()
		}
	}
	return count, size
}

// scanIndex walks the CAS directory and builds an in-memory index of hashes → last accessed.
// This is used for LRU eviction and existence checks without disk I/O.
func (c *CAS) scanIndex() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.index = make(map[string]time.Time)
	err := filepath.Walk(c.baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		// rel format: "ab/cd/abcdef1234..." → hash is filename
		hash := filepath.Base(path)
		if len(hash) >= 8 { // reasonable hash length
			c.index[hash] = info.ModTime()
		}
		return nil
	})
	return err
}
