package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewResultCacheDisabled(t *testing.T) {
	cfg := DefaultCacheConfig()
	cfg.Enabled = false
	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Expected nil error for disabled cache, got: %v", err)
	}
	if cache != nil {
		t.Fatal("Expected nil cache when disabled")
	}
}

func TestNewResultCacheEnabled(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "test_cache.db")
	cfg.MaxEntries = 100

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	if cache == nil {
		t.Fatal("Expected non-nil cache")
	}
}

func TestCachePutAndGet(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")
	cfg.DefaultTTL = 1 * time.Hour

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	events := []Event{
		{Target: "acme-corp.io", Source: "test", Type: "subdomain"},
		{Target: "api.acme-corp.io", Source: "test", Type: "subdomain"},
	}

	err = cache.Put("subfinder", []string{"acme-corp.io"}, 10, events)
	if err != nil {
		t.Fatalf("Failed to put cache entry: %v", err)
	}

	entry, ok := cache.Get("subfinder", []string{"acme-corp.io"}, 10)
	if !ok {
		t.Fatal("Expected cache hit")
	}
	if len(entry.Events) != 2 {
		t.Fatalf("Expected 2 events, got %d", len(entry.Events))
	}
	if entry.Events[0].Target != "acme-corp.io" {
		t.Errorf("Expected target 'acme-corp.io', got '%s'", entry.Events[0].Target)
	}
}

func TestCacheGetNoHit(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	entry, ok := cache.Get("nonexistent", []string{"acme-corp.io"}, 5)
	if ok {
		t.Fatal("Expected cache miss")
	}
	if entry != nil {
		t.Fatal("Expected nil entry on miss")
	}
}

func TestCacheGetNilCache(t *testing.T) {
	var cache *ResultCache
	entry, ok := cache.Get("test", []string{"acme-corp.io"}, 5)
	if ok {
		t.Fatal("Expected false from nil cache")
	}
	if entry != nil {
		t.Fatal("Expected nil entry from nil cache")
	}
}

func TestCachePutNilCache(t *testing.T) {
	var cache *ResultCache
	err := cache.Put("test", []string{"acme-corp.io"}, 5, nil)
	if err != nil {
		t.Fatalf("Expected nil error from nil cache, got: %v", err)
	}
}

func TestCacheInvalidate(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	err = cache.Put("test", []string{"acme-corp.io"}, 5, []Event{{Target: "acme-corp.io"}})
	if err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	err = cache.Invalidate("test", []string{"acme-corp.io"}, 5)
	if err != nil {
		t.Fatalf("Failed to invalidate: %v", err)
	}

	_, ok := cache.Get("test", []string{"acme-corp.io"}, 5)
	if ok {
		t.Fatal("Expected miss after invalidation")
	}
}

func TestCacheInvalidateAll(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	_ = cache.Put("tool1", []string{"a.com"}, 5, []Event{{Target: "a.com"}})
	_ = cache.Put("tool2", []string{"b.com"}, 5, []Event{{Target: "b.com"}})

	err = cache.InvalidateAll()
	if err != nil {
		t.Fatalf("Failed to invalidate all: %v", err)
	}

	_, ok := cache.Get("tool1", []string{"a.com"}, 5)
	if ok {
		t.Fatal("Expected miss after invalidate all")
	}
}

func TestCacheStats(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")
	cfg.DefaultTTL = 1 * time.Hour

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	stats := cache.Stats()
	if stats["enabled"] != true {
		t.Error("Expected cache enabled")
	}

	_ = cache.Put("test", []string{"acme-corp.io"}, 5, []Event{{Target: "acme-corp.io"}})

	stats = cache.Stats()
	total := stats["total_entries"].(int)
	if total != 1 {
		t.Errorf("Expected 1 total entry, got %d", total)
	}
}

func TestCacheStatsNil(t *testing.T) {
	var cache *ResultCache
	stats := cache.Stats()
	if stats["enabled"] != false {
		t.Error("Expected disabled stats for nil cache")
	}
}

func TestCacheKeyDeterministic(t *testing.T) {
	key1 := CacheKey("nuclei", []string{"a.com", "b.com"}, 5)
	key2 := CacheKey("nuclei", []string{"a.com", "b.com"}, 5)
	if key1 != key2 {
		t.Error("CacheKey should be deterministic for same inputs")
	}
}

func TestCacheKeyDifferentOrder(t *testing.T) {
	key1 := CacheKey("nuclei", []string{"a.com", "b.com"}, 5)
	key2 := CacheKey("nuclei", []string{"b.com", "a.com"}, 5)
	if key1 == key2 {
		t.Error("CacheKey should differ when target order differs")
	}
}

func TestCacheKeyDifferentTool(t *testing.T) {
	key1 := CacheKey("nuclei", []string{"a.com"}, 5)
	key2 := CacheKey("httpx", []string{"a.com"}, 5)
	if key1 == key2 {
		t.Error("CacheKey should differ for different tools")
	}
}

func TestCacheExpiry(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")
	cfg.DefaultTTL = 10 * time.Millisecond

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	err = cache.Put("test", []string{"acme-corp.io"}, 5, []Event{{Target: "acme-corp.io"}})
	if err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	_, ok := cache.Get("test", []string{"acme-corp.io"}, 5)
	if ok {
		t.Fatal("Expected cache miss after TTL expiry")
	}
}

func TestCacheTTLOverride(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")
	cfg.DefaultTTL = 1 * time.Hour
	cfg.ToolTTLOverrides = map[string]time.Duration{
		"crtsh": 5 * time.Millisecond,
	}

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	err = cache.Put("crtsh", []string{"acme-corp.io"}, 5, []Event{{Target: "acme-corp.io"}})
	if err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	_, ok := cache.Get("crtsh", []string{"acme-corp.io"}, 5)
	if ok {
		t.Fatal("Expected miss after tool-specific TTL expiry")
	}
}

func TestCacheClose(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}

	err = cache.Close()
	if err != nil {
		t.Fatalf("Failed to close cache: %v", err)
	}
}

func TestCacheCloseNil(t *testing.T) {
	var cache *ResultCache
	err := cache.Close()
	if err != nil {
		t.Fatalf("Expected nil error closing nil cache, got: %v", err)
	}
}

func TestCacheInvalidateNil(t *testing.T) {
	var cache *ResultCache
	err := cache.Invalidate("test", []string{"a.com"}, 5)
	if err != nil {
		t.Fatalf("Expected nil error from nil cache, got: %v", err)
	}
}

func TestCacheInvalidateAllNil(t *testing.T) {
	var cache *ResultCache
	err := cache.InvalidateAll()
	if err != nil {
		t.Fatalf("Expected nil error from nil cache, got: %v", err)
	}
}

func TestCacheDBPathCreation(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "subdir", "nested")
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(nested, "cache.db")

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache with nested path: %v", err)
	}
	defer cache.Close()

	if _, err := os.Stat(nested); os.IsNotExist(err) {
		t.Fatal("Expected cache to create directory")
	}
}

func TestCacheOverwrite(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	err = cache.Put("test", []string{"a.com"}, 5, []Event{{Target: "a.com"}})
	if err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	// Overwrite with different data
	err = cache.Put("test", []string{"a.com"}, 5, []Event{{Target: "a.com", Source: "updated"}})
	if err != nil {
		t.Fatalf("Failed to overwrite: %v", err)
	}

	entry, ok := cache.Get("test", []string{"a.com"}, 5)
	if !ok {
		t.Fatal("Expected cache hit after overwrite")
	}
	if len(entry.Events) != 1 || entry.Events[0].Source != "updated" {
		t.Error("Expected overwritten data")
	}
}

func TestCacheHitCount(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")
	cfg.DefaultTTL = 1 * time.Hour

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	err = cache.Put("test", []string{"a.com"}, 5, []Event{{Target: "a.com"}})
	if err != nil {
		t.Fatalf("Failed to put: %v", err)
	}

	// Multiple hits
	for i := 0; i < 3; i++ {
		_, ok := cache.Get("test", []string{"a.com"}, 5)
		if !ok {
			t.Fatal("Expected hit on iteration", i)
		}
	}

	// Give async hit-count goroutines time to complete
	time.Sleep(50 * time.Millisecond)

	stats := cache.Stats()
	hits := stats["total_hits"].(int64)
	if hits < 3 {
		t.Errorf("Expected at least 3 total hits, got %d", hits)
	}
}

func TestCacheConcurrentAccess(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultCacheConfig()
	cfg.Enabled = true
	cfg.DBPath = filepath.Join(dir, "cache.db")
	cfg.DefaultTTL = 1 * time.Hour

	cache, err := NewResultCache(cfg)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 20; j++ {
				target := strings.ToLower(string(rune('a'+(j%26)))) + ".com"
				_ = cache.Put("test", []string{target}, 5, []Event{{Target: target}})
				_, _ = cache.Get("test", []string{target}, 5)
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestDefaultCacheConfig(t *testing.T) {
	cfg := DefaultCacheConfig()
	if !cfg.Enabled {
		t.Error("Default cache should be enabled")
	}
	if cfg.DefaultTTL != 4*time.Hour {
		t.Errorf("Expected default TTL 4h, got %v", cfg.DefaultTTL)
	}
	if cfg.MaxEntries != 10000 {
		t.Errorf("Expected max entries 10000, got %d", cfg.MaxEntries)
	}
	if _, ok := cfg.ToolTTLOverrides["crtsh"]; !ok {
		t.Error("Expected crtsh TTL override")
	}
}
