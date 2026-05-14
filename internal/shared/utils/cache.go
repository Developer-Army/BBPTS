package utils

import (
	"sync"
)

// Cache is a thread-safe set for deduplicating URLs, domains, or IP addresses.
// It uses a simple native map with a RWMutex.
type Cache struct {
	mu   sync.RWMutex
	seen map[string]struct{}
}

// New creates a new deduplication Cache.
func New() *Cache {
	return &Cache{
		seen: make(map[string]struct{}),
	}
}

// Add checks if a key is in the cache, and if not, adds it.
// It returns true if the item was added (meaning it's new),
// and false if it was already in the cache (a duplicate).
func (c *Cache) Add(key string) bool {
	c.mu.RLock()
	_, exists := c.seen[key]
	c.mu.RUnlock()

	if exists {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// Double check to avoid race condition
	if _, exists := c.seen[key]; exists {
		return false
	}
	c.seen[key] = struct{}{}
	return true
}

// Contains checks if a key is already in the cache.
func (c *Cache) Contains(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.seen[key]
	return exists
}

// Clear empties the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = make(map[string]struct{})
}
