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

type CAS struct {
	baseDir string
	mu      sync.RWMutex         // protects concurrent Store/Retrieve
	index   map[string]time.Time // hash → last accessed (for LRU eviction)
	maxSize int64                // optional quota in bytes (0 = unlimited)
}

func (c *CAS) objectPath(hashStr string) string {
	if len(hashStr) < 4 {
		return filepath.Join(c.baseDir, hashStr)
	}
	shardDir := filepath.Join(c.baseDir, hashStr[:2], hashStr[2:4])
	return filepath.Join(shardDir, hashStr)
}

type CASOption func(*CAS)

func WithMaxSize(bytes int64) CASOption {
	return func(c *CAS) {
		c.maxSize = bytes
	}
}

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

	if err := c.scanIndex(); err != nil {
		slog.Warn("CAS scan failed, starting fresh", "error", err)
	}

	return c, nil
}

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

	c.mu.RLock()
	if _, exists := c.index[hashStr]; exists {

		if err := os.Chtimes(objectPath, time.Now(), time.Now()); err == nil {
			c.index[hashStr] = time.Now()
		}
		c.mu.RUnlock()
		return hashStr, nil
	}
	c.mu.RUnlock()

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

	c.mu.Lock()
	c.index[hashStr] = time.Now()
	if c.maxSize > 0 {
		c.evictIfNeeded()
	}
	c.mu.Unlock()

	return hashStr, nil
}

func (c *CAS) evictIfNeeded() {
	// Compute current total size
	var currentSize int64
	for hashStr := range c.index {
		path := c.objectPath(hashStr)
		if info, err := os.Stat(path); err == nil {
			currentSize += info.Size()
		}
	}

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

func (c *CAS) Retrieve(hashStr string) ([]byte, error) {
	if len(hashStr) < 4 {
		return nil, fmt.Errorf("invalid hash")
	}

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
	defer func() { _ = gz.Close() }()

	var buf bytes.Buffer
	// Limit decompression to 256MB to prevent decompression bombs
	if _, err := io.Copy(&buf, io.LimitReader(gz, 256*1024*1024)); err != nil {
		return nil, fmt.Errorf("failed to read decompressed data: %w", err)
	}

	c.mu.Lock()
	c.index[hashStr] = time.Now()
	c.mu.Unlock()

	return buf.Bytes(), nil
}

func (c *CAS) Exists(hashStr string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	path := c.objectPath(hashStr)
	_, err := os.Stat(path)
	return err == nil
}

func (c *CAS) Delete(hashStr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.objectPath(hashStr)
	return os.Remove(path)
}

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

		hash := filepath.Base(path)
		if len(hash) >= 8 {
			c.index[hash] = info.ModTime()
		}
		return nil
	})
	return err
}
