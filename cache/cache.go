package cache

import (
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
	AddOrUpdate(u interface{}, value interface{})
	Get(u interface{}) (i interface{}, err error)
	GetReset(u interface{}, duration time.Duration) (interface{}, error)
	Remove(u interface{}) (err error)
	LockedModify(u interface{}, add func(a, b interface{}) interface{}, increment interface{}) (interface{}, error)
	SetTimeOut(u interface{}, timeout time.Duration) (err error)
}

// Cache is the structure that involves the map of entries. The cache
// provides a sync mechanism and allows multiple clients at the same time.
type Cache struct {
	data     map[interface{}]entry
	lifetime time.Duration
	sync.RWMutex
	expirer ExpirationNotifier
}

// entry is a single line in the datastore that includes the actual entry
// and the time that entry was created or updated
type entry struct {
	value     interface{}
	timestamp time.Time
	timer     *time.Timer
	expirer   ExpirationNotifier
}

// NewCache creates a new data cache
func NewCache() *Cache {

	c := &Cache{
		data:     make(map[interface{}]entry),
		lifetime: -1,
	}

	return c
}

// NewCacheWithExpiration creates a new data cache
func NewCacheWithExpiration(lifetime time.Duration) *Cache {

	return &Cache{
		data:     make(map[interface{}]entry),
		lifetime: lifetime,
	}
}

// NewCacheWithExpirationNotifier creates a new data cache with notifier
func NewCacheWithExpirationNotifier(lifetime time.Duration, expirer ExpirationNotifier) *Cache {

	return &Cache{
		data:     make(map[interface{}]entry),
		lifetime: lifetime,
		expirer:  expirer,
	}
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
		return nil
	}

	return fmt.Errorf("Item Exists - Use update")
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

	return nil, fmt.Errorf("Cannot read item - it doesn't exist")
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

	return fmt.Errorf("Cannot update item - it doesn't exist")
}

// AddOrUpdate adds a new value in the cache or updates the existing value
// if needed. If an update happens the timestamp is also updated.
func (c *Cache) AddOrUpdate(u interface{}, value interface{}) {

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
	}

	c.data[u] = entry{
		value:     value,
		timestamp: t,
		timer:     timer,
		expirer:   c.expirer,
	}

}

// SetTimeOut sets the time out of an entry to a new value
func (c *Cache) SetTimeOut(u interface{}, timeout time.Duration) (err error) {
	c.Lock()
	defer c.Unlock()

	if _, ok := c.data[u]; !ok {
		return fmt.Errorf("Item is deleted already")
	}

	c.data[u].timer.Reset(timeout)

	return nil
}

// Get retrieves the entry from the cache
func (c *Cache) Get(u interface{}) (i interface{}, err error) {

	c.Lock()
	defer c.Unlock()

	if _, ok := c.data[u]; !ok {
		return nil, fmt.Errorf("Item does not exist")
	}

	return c.data[u].value, nil
}

// removeNotify removes the entry from the cache and optionally notifies.
// returns error if not there
func (c *Cache) removeNotify(u interface{}, notify bool) (err error) {

	c.Lock()
	defer c.Unlock()

	val, ok := c.data[u]
	if !ok {
		return fmt.Errorf("Item does not exist")
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
		return nil, fmt.Errorf("Item not found")
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
