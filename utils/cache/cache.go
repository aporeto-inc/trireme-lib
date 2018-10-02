package cache

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// ExpirationNotifier is a function which will be called every time a cache
// expires an item
type ExpirationNotifier func(c DataStore, id interface{}, item interface{})

// DataStore is the interface to a datastore.
type DataStore interface {
	Add(u interface{}, value interface{}) (err error)
	AddOrUpdate(u interface{}, value interface{}) bool
	Get(u interface{}) (i interface{}, err error)
	GetReset(u interface{}, duration time.Duration) (interface{}, error)
	Remove(u interface{}) (err error)
	RemoveWithDelay(u interface{}, duration time.Duration) (err error)
	LockedModify(u interface{}, add func(a, b interface{}) interface{}, increment interface{}) (interface{}, error)
	SetTimeOut(u interface{}, timeout time.Duration) (err error)
	KeyList() []interface{}
	ToString() string
}

// Cache is the structure that involves the map of entries. The cache
// provides a sync mechanism and allows multiple clients at the same time.
type Cache struct {
	name     string
	data     map[interface{}]entry
	lifetime time.Duration
	sync.RWMutex
	expirer ExpirationNotifier
	max     int
}

// entry is a single line in the datastore that includes the actual entry
// and the time that entry was created or updated
type entry struct {
	value     interface{}
	timestamp time.Time
	timer     *time.Timer
	expirer   ExpirationNotifier
}

// cacheRegistry keeps handles of all caches initialized through this library
// for book keeping
type cacheRegistry struct {
	sync.RWMutex
	items map[string]*Cache
}

var registry *cacheRegistry

func init() {

	registry = &cacheRegistry{
		items: make(map[string]*Cache),
	}
}

// Add adds a cache to a registry
func (r *cacheRegistry) Add(c *Cache) {
	r.Lock()
	defer r.Unlock()

	r.items[c.name] = c
}

// ToString generates information about all caches initialized through this lib
func (r *cacheRegistry) ToString() string {
	r.Lock()
	defer r.Unlock()

	buffer := fmt.Sprintf("Cache Registry: %d\n", len(r.items))
	buffer += fmt.Sprintf(" %32s : %s\n\n", "Cache Name", "max/curr")
	for k, c := range r.items {
		buffer += fmt.Sprintf(" %32s : %s\n", k, c.ToString())
	}
	return buffer
}

// NewCache creates a new data cache
func NewCache(name string) *Cache {

	return NewCacheWithExpirationNotifier(name, -1, nil)
}

// NewCacheWithExpiration creates a new data cache
func NewCacheWithExpiration(name string, lifetime time.Duration) *Cache {

	return NewCacheWithExpirationNotifier(name, lifetime, nil)
}

// NewCacheWithExpirationNotifier creates a new data cache with notifier
func NewCacheWithExpirationNotifier(name string, lifetime time.Duration, expirer ExpirationNotifier) *Cache {

	c := &Cache{
		name:     name,
		data:     make(map[interface{}]entry),
		lifetime: lifetime,
		expirer:  expirer,
	}
	c.max = len(c.data)
	registry.Add(c)
	return c
}

// ToString generates information about all caches initialized through this lib
func ToString() string {

	return registry.ToString()
}

// ToString provides statistics about this cache
func (c *Cache) ToString() string {
	c.Lock()
	defer c.Unlock()

	return fmt.Sprintf("%d/%d", c.max, len(c.data))
}

// Add stores an entry into the cache and updates the timestamp
func (c *Cache) Add(u interface{}, value interface{}) (err error) {

	var timer *time.Timer
	if c.lifetime != -1 {
		timer = time.AfterFunc(c.lifetime, func() {
			if err := c.removeNotify(u, true); err != nil {
				zap.L().Warn("Failed to remove item", zap.String("key", fmt.Sprintf("%v", u)))
			}
		})
	}

	t := time.Now()

	c.Lock()
	defer c.Unlock()

	if _, ok := c.data[u]; !ok {

		c.data[u] = entry{
			value:     value,
			timestamp: t,
			timer:     timer,
			expirer:   c.expirer,
		}
		if len(c.data) > c.max {
			c.max = len(c.data)
		}
		return nil
	}

	return errors.New("item exists: use update")
}

// GetReset  changes the value of an entry into the cache and updates the timestamp
func (c *Cache) GetReset(u interface{}, duration time.Duration) (interface{}, error) {

	c.Lock()
	defer c.Unlock()

	if line, ok := c.data[u]; ok {

		if c.lifetime != -1 && line.timer != nil {
			if duration > 0 {
				line.timer.Reset(duration)
			} else {
				line.timer.Reset(c.lifetime)
			}
		}

		return line.value, nil
	}

	return nil, errors.New("cannot read item: not found")
}

// Update changes the value of an entry into the cache and updates the timestamp
func (c *Cache) Update(u interface{}, value interface{}) (err error) {

	var timer *time.Timer
	if c.lifetime != -1 {
		timer = time.AfterFunc(c.lifetime, func() {
			if err := c.removeNotify(u, true); err != nil {
				zap.L().Warn("Failed to remove item", zap.String("key", fmt.Sprintf("%v", u)))
			}
		})
	}

	t := time.Now()

	c.Lock()
	defer c.Unlock()

	if _, ok := c.data[u]; ok {

		if c.data[u].timer != nil {
			c.data[u].timer.Stop()
		}

		c.data[u] = entry{
			value:     value,
			timestamp: t,
			timer:     timer,
			expirer:   c.expirer,
		}

		return nil
	}

	return errors.New("cannot update item: not found")
}

// AddOrUpdate adds a new value in the cache or updates the existing value
// if needed. If an update happens the timestamp is also updated.
// Returns true if key was updated.
func (c *Cache) AddOrUpdate(u interface{}, value interface{}) (updated bool) {

	var timer *time.Timer
	if c.lifetime != -1 {
		timer = time.AfterFunc(c.lifetime, func() {
			if err := c.removeNotify(u, true); err != nil {
				zap.L().Warn("Failed to remove item", zap.String("key", fmt.Sprintf("%v", u)))
			}
		})
	}

	t := time.Now()

	c.Lock()
	defer c.Unlock()

	if _, updated = c.data[u]; updated {
		if c.data[u].timer != nil {
			c.data[u].timer.Stop()
		}
	}

	c.data[u] = entry{
		value:     value,
		timestamp: t,
		timer:     timer,
		expirer:   c.expirer,
	}
	if len(c.data) > c.max {
		c.max = len(c.data)
	}

	return updated
}

// SetTimeOut sets the time out of an entry to a new value
func (c *Cache) SetTimeOut(u interface{}, timeout time.Duration) (err error) {
	c.Lock()
	defer c.Unlock()

	if _, ok := c.data[u]; !ok {
		return errors.New("item is already deleted")
	}

	c.data[u].timer.Reset(timeout)

	return nil
}

// Get retrieves the entry from the cache
func (c *Cache) Get(u interface{}) (i interface{}, err error) {

	c.Lock()
	defer c.Unlock()

	if _, ok := c.data[u]; !ok {
		return nil, errors.New("not found")
	}

	return c.data[u].value, nil
}

// KeyList returns all the keys that are currently stored in the cache.
func (c *Cache) KeyList() []interface{} {
	c.Lock()
	defer c.Unlock()

	list := []interface{}{}
	for k := range c.data {
		list = append(list, k)
	}
	return list
}

// removeNotify removes the entry from the cache and optionally notifies.
// returns error if not there
func (c *Cache) removeNotify(u interface{}, notify bool) (err error) {

	c.Lock()
	defer c.Unlock()

	val, ok := c.data[u]
	if !ok {
		return errors.New("not found")
	}

	if val.timer != nil {
		val.timer.Stop()
	}

	if notify && val.expirer != nil {
		val.expirer(c, u, val.value)
	}

	delete(c.data, u)

	return nil
}

// Remove removes the entry from the cache and returns error if not there
func (c *Cache) Remove(u interface{}) (err error) {

	return c.removeNotify(u, false)
}

// RemoveWithDelay removes the entry from the cache after a certain duration
func (c *Cache) RemoveWithDelay(u interface{}, duration time.Duration) error {
	if duration == -1 {
		return c.Remove(u)
	}

	c.Lock()
	defer c.Unlock()

	e, ok := c.data[u]

	if !ok {
		return errors.New("cannot remove item with delay: not found")
	}

	timer := time.AfterFunc(duration, func() {
		if err := c.Remove(u); err != nil {
			zap.L().Warn("Failed to remove item with delay", zap.String("key", fmt.Sprintf("%v", u)), zap.String("delay", duration.String()))
		}
	})

	t := time.Now()

	if c.data[u].timer != nil {
		c.data[u].timer.Stop()
	}

	c.data[u] = entry{
		value:     e.value,
		timestamp: t,
		timer:     timer,
		expirer:   c.expirer,
	}

	return nil

}

// SizeOf returns the number of elements in the cache
func (c *Cache) SizeOf() int {

	c.Lock()
	defer c.Unlock()

	return len(c.data)
}

// LockedModify  locks the data store
func (c *Cache) LockedModify(u interface{}, add func(a, b interface{}) interface{}, increment interface{}) (interface{}, error) {

	var timer *time.Timer
	if c.lifetime != -1 {
		timer = time.AfterFunc(c.lifetime, func() {
			if err := c.removeNotify(u, true); err != nil {
				zap.L().Warn("Failed to remove item", zap.String("key", fmt.Sprintf("%v", u)))
			}
		})
	}

	t := time.Now()

	c.Lock()
	defer c.Unlock()

	e, ok := c.data[u]
	if !ok {
		return nil, errors.New("not found")
	}

	if e.timer != nil {
		e.timer.Stop()
	}

	e.value = add(e.value, increment)
	e.timer = timer
	e.timestamp = t
	e.expirer = c.expirer

	c.data[u] = e

	return e.value, nil

}
