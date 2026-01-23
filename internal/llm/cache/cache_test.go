package cache

import (
	"testing"
	"time"
)

func TestNewCache(t *testing.T) {
	c := New(100, 5*time.Minute)
	if c == nil {
		t.Fatal("expected non-nil cache")
	}
	if c.Len() != 0 {
		t.Errorf("expected empty cache, got %d", c.Len())
	}
}

func TestCache_SetGet(t *testing.T) {
	c := New(100, 5*time.Minute)

	c.Set("key1", "value1")
	val, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected to find key1")
	}
	if val != "value1" {
		t.Errorf("expected value1, got %v", val)
	}
}

func TestCache_GetMiss(t *testing.T) {
	c := New(100, 5*time.Minute)

	val, ok := c.Get("nonexistent")
	if ok {
		t.Error("expected not to find nonexistent key")
	}
	if val != nil {
		t.Errorf("expected nil value, got %v", val)
	}

	stats := c.Stats()
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}

func TestCache_Expiration(t *testing.T) {
	c := New(100, 10*time.Millisecond)

	c.Set("key1", "value1")
	time.Sleep(20 * time.Millisecond)

	val, ok := c.Get("key1")
	if ok {
		t.Error("expected key to be expired")
	}
	if val != nil {
		t.Errorf("expected nil value for expired key, got %v", val)
	}
}

func TestCache_LRUEviction(t *testing.T) {
	c := New(3, 5*time.Minute)

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Set("key3", "value3")

	// Access key1 to make it recently used
	c.Get("key1")

	// Add key4, should evict key2 (least recently used)
	c.Set("key4", "value4")

	// key2 should be evicted
	_, ok := c.Get("key2")
	if ok {
		t.Error("expected key2 to be evicted")
	}

	// key1 should still exist
	_, ok = c.Get("key1")
	if !ok {
		t.Error("expected key1 to still exist")
	}
}

func TestCache_Update(t *testing.T) {
	c := New(100, 5*time.Minute)

	c.Set("key1", "value1")
	c.Set("key1", "value2")

	val, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected to find key1")
	}
	if val != "value2" {
		t.Errorf("expected value2, got %v", val)
	}
}

func TestCache_Delete(t *testing.T) {
	c := New(100, 5*time.Minute)

	c.Set("key1", "value1")
	c.Delete("key1")

	_, ok := c.Get("key1")
	if ok {
		t.Error("expected key to be deleted")
	}
}

func TestCache_Clear(t *testing.T) {
	c := New(100, 5*time.Minute)

	c.Set("key1", "value1")
	c.Set("key2", "value2")
	c.Clear()

	if c.Len() != 0 {
		t.Errorf("expected empty cache after clear, got %d", c.Len())
	}
}

func TestCache_Cleanup(t *testing.T) {
	c := New(100, 10*time.Millisecond)

	c.Set("key1", "value1")
	c.Set("key2", "value2")

	time.Sleep(20 * time.Millisecond)

	removed := c.Cleanup()
	if removed != 2 {
		t.Errorf("expected 2 entries removed, got %d", removed)
	}

	if c.Len() != 0 {
		t.Errorf("expected empty cache after cleanup, got %d", c.Len())
	}
}

func TestCache_SetWithTTL(t *testing.T) {
	c := New(100, 5*time.Minute)

	// Set with custom short TTL
	c.SetWithTTL("key1", "value1", 10*time.Millisecond)

	// Should exist immediately
	val, ok := c.Get("key1")
	if !ok {
		t.Fatal("expected to find key1")
	}
	if val != "value1" {
		t.Errorf("expected value1, got %v", val)
	}

	// Wait for expiration
	time.Sleep(20 * time.Millisecond)

	_, ok = c.Get("key1")
	if ok {
		t.Error("expected key1 to be expired")
	}
}

func TestCache_Stats(t *testing.T) {
	c := New(100, 5*time.Minute)

	c.Set("key1", "value1")
	c.Get("key1")      // hit
	c.Get("key1")      // hit
	c.Get("nonexistent") // miss

	stats := c.Stats()
	if stats.Hits != 2 {
		t.Errorf("expected 2 hits, got %d", stats.Hits)
	}
	if stats.Misses != 1 {
		t.Errorf("expected 1 miss, got %d", stats.Misses)
	}
}

func TestHashKey(t *testing.T) {
	key1 := HashKey("test", 123, map[string]string{"a": "b"})
	key2 := HashKey("test", 123, map[string]string{"a": "b"})
	key3 := HashKey("different", 123, map[string]string{"a": "b"})

	if key1 != key2 {
		t.Error("expected same inputs to produce same hash")
	}
	if key1 == key3 {
		t.Error("expected different inputs to produce different hash")
	}
	if len(key1) != 32 {
		t.Errorf("expected 32 character hash, got %d", len(key1))
	}
}
