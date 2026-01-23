// Package cache provides an LRU cache with TTL for LLM responses.
package cache

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"
)

// Cache is an LRU cache with TTL support.
type Cache struct {
	mu         sync.RWMutex
	maxEntries int
	ttl        time.Duration
	items      map[string]*list.Element
	evictList  *list.List
	stats      Stats
}

// entry represents a cached item.
type entry struct {
	key       string
	value     interface{}
	expiresAt time.Time
}

// Stats tracks cache statistics.
type Stats struct {
	Hits       int64
	Misses     int64
	Evictions  int64
	Expirations int64
}

// New creates a new cache with the given capacity and TTL.
func New(maxEntries int, ttl time.Duration) *Cache {
	return &Cache{
		maxEntries: maxEntries,
		ttl:        ttl,
		items:      make(map[string]*list.Element),
		evictList:  list.New(),
	}
}

// Get retrieves a value from the cache.
// Returns the value and true if found and not expired, nil and false otherwise.
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.items[key]
	if !ok {
		c.stats.Misses++
		return nil, false
	}

	ent := elem.Value.(*entry)

	// Check if expired
	if time.Now().After(ent.expiresAt) {
		c.removeElement(elem)
		c.stats.Expirations++
		c.stats.Misses++
		return nil, false
	}

	// Move to front (most recently used)
	c.evictList.MoveToFront(elem)
	c.stats.Hits++
	return ent.value, true
}

// Set adds a value to the cache.
func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if elem, ok := c.items[key]; ok {
		c.evictList.MoveToFront(elem)
		ent := elem.Value.(*entry)
		ent.value = value
		ent.expiresAt = time.Now().Add(c.ttl)
		return
	}

	// Add new entry
	ent := &entry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(c.ttl),
	}
	elem := c.evictList.PushFront(ent)
	c.items[key] = elem

	// Evict oldest if over capacity
	for c.evictList.Len() > c.maxEntries {
		c.removeOldest()
	}
}

// SetWithTTL adds a value with a custom TTL.
func (c *Cache) SetWithTTL(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if key already exists
	if elem, ok := c.items[key]; ok {
		c.evictList.MoveToFront(elem)
		ent := elem.Value.(*entry)
		ent.value = value
		ent.expiresAt = time.Now().Add(ttl)
		return
	}

	// Add new entry
	ent := &entry{
		key:       key,
		value:     value,
		expiresAt: time.Now().Add(ttl),
	}
	elem := c.evictList.PushFront(ent)
	c.items[key] = elem

	// Evict oldest if over capacity
	for c.evictList.Len() > c.maxEntries {
		c.removeOldest()
	}
}

// Delete removes a value from the cache.
func (c *Cache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if elem, ok := c.items[key]; ok {
		c.removeElement(elem)
	}
}

// Clear removes all entries from the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items = make(map[string]*list.Element)
	c.evictList.Init()
}

// Len returns the current number of entries in the cache.
func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.evictList.Len()
}

// Stats returns cache statistics.
func (c *Cache) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// Cleanup removes expired entries. Call periodically for active cleanup.
func (c *Cache) Cleanup() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0

	for elem := c.evictList.Back(); elem != nil; {
		ent := elem.Value.(*entry)
		if now.After(ent.expiresAt) {
			prev := elem.Prev()
			c.removeElement(elem)
			c.stats.Expirations++
			removed++
			elem = prev
		} else {
			elem = elem.Prev()
		}
	}

	return removed
}

// removeOldest removes the oldest entry.
func (c *Cache) removeOldest() {
	elem := c.evictList.Back()
	if elem != nil {
		c.removeElement(elem)
		c.stats.Evictions++
	}
}

// removeElement removes an element from the cache.
func (c *Cache) removeElement(elem *list.Element) {
	c.evictList.Remove(elem)
	ent := elem.Value.(*entry)
	delete(c.items, ent.key)
}

// HashKey creates a cache key from arbitrary data by hashing it.
func HashKey(data ...interface{}) string {
	h := sha256.New()
	for _, d := range data {
		b, _ := json.Marshal(d)
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}
