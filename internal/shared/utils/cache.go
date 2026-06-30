package utils

import (
	"sync"
)

type Cache struct {
	mu   sync.RWMutex
	seen map[string]struct{}
}

func New() *Cache {
	return &Cache{
		seen: make(map[string]struct{}),
	}
}

func (c *Cache) Add(key string) bool {
	c.mu.RLock()
	_, exists := c.seen[key]
	c.mu.RUnlock()

	if exists {
		return false
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.seen[key]; exists {
		return false
	}
	c.seen[key] = struct{}{}
	return true
}

func (c *Cache) Contains(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.seen[key]
	return exists
}

func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seen = make(map[string]struct{})
}
