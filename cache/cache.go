package cache

import (
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
)

//DataStore is the interface to a datastore that will evolve to hold basic
//values and also auto-refresh the cache. The DataStore is indexed by
// UUID values only
type DataStore interface {
	Add(u interface{}, value interface{}) (err error)
	AddOrUpdate(u interface{}, value interface{}) (err error)
	Get(u interface{}) (i interface{}, err error)
	Remove(u interface{}) (err error)
	Refresh(d time.Duration)
	DumpStore()
	LockedModify(u interface{}, add func(a, b interface{}) interface{}, increment interface{}) (interface{}, error)
}

//Cleanable is an interface that could be implemented by elements being
//inserted in cache with expiration
type Cleanable interface {
	Cleanup()
}

//Cache is the structure that involves the map of entries. The cache
//provides a sync mechanism and allows multiple clients at the same time.
//For example one thread might be storing values in the cache while
//a parallel thread is refreshing the cache.
type Cache struct {
	data        map[interface{}]entry
	refresh     func(val interface{}) interface{}
	calendar    chan calendarEntry
	lifetime    time.Duration
	autocollect bool
	sync.RWMutex
}

//entry is a single line in the datastore that includes the actual entry
//and the time that entry was created or updated
type entry struct {
	value     interface{}
	timestamp time.Time
}

// calendarEntry
type calendarEntry struct {
	u         interface{}
	timestamp time.Time
}

//defaultRefresh is the default refresh function that doesn't do much
//Users of the package can provide their refresh function.
func defaultRefresh(val interface{}) interface{} {
	return val
}

//NewCache creates a new data cache
func NewCache(refresh func(val interface{}) interface{}) *Cache {
	var c Cache
	c.data = make(map[interface{}]entry)
	if refresh != nil {
		c.refresh = refresh
	} else {
		c.refresh = defaultRefresh
	}
	c.autocollect = false
	return &c
}

//NewCacheWithExpiration creates a new data cache
func NewCacheWithExpiration(lifetime time.Duration, length int) *Cache {
	var c Cache
	c.data = make(map[interface{}]entry)

	c.calendar = make(chan calendarEntry, length)
	c.lifetime = lifetime
	c.autocollect = true
	go c.collect()
	return &c
}

// schedule inserts an entry into a queue to delete the flow after the expiration time
func (c *Cache) schedule(t time.Time, u interface{}) {

	entry := calendarEntry{
		u:         u,
		timestamp: t.Add(c.lifetime),
	}
	select {
	case c.calendar <- entry:
	default:
	}
}

// collect processes calendar entries and removes flows from the cache after they have expired
func (c *Cache) collect() {

	for entry := range c.calendar {
		if entry.timestamp.After(time.Now()) {
			wait := entry.timestamp.Sub(time.Now())
			time.Sleep(wait)
		}
		c.Remove(entry.u)
	}
}

//Add stores an entry into the cache and updates the timestamp
func (c *Cache) Add(u interface{}, value interface{}) (err error) {
	c.Lock()
	defer c.Unlock()
	t := time.Now()
	if _, ok := c.data[u]; !ok {
		c.data[u] = entry{value, t}
		if c.autocollect {
			c.schedule(t.Add(c.lifetime), u)
		}
		return nil
	}
	return fmt.Errorf("Item Exists - Use update")
}

//Update changes the value of an entry into the cache and updates the timestamp
func (c *Cache) Update(u interface{}, value interface{}) (err error) {
	c.Lock()
	defer c.Unlock()
	t := time.Now()
	if _, ok := c.data[u]; ok {
		c.data[u] = entry{value, t}
		if c.autocollect {
			c.schedule(t.Add(c.lifetime), u)
		}
		return nil
	}
	return fmt.Errorf("Cannot update item - it doesn't exist")
}

//AddOrUpdate adds a new value in the cache or updates the existing value
//if needed. If an update happens the timestamp is also updated.
func (c *Cache) AddOrUpdate(u interface{}, value interface{}) (err error) {
	c.Lock()
	defer c.Unlock()
	t := time.Now()
	c.data[u] = entry{value, t}
	if c.autocollect {
		c.schedule(t.Add(c.lifetime), u)
	}
	return nil
}

//Get retrieves the entry from the cache
func (c *Cache) Get(u interface{}) (i interface{}, err error) {
	c.Lock()
	defer c.Unlock()

	if _, ok := c.data[u]; !ok {
		return nil, fmt.Errorf("Item does not exist.")
	}

	return c.data[u].value, nil

}

//Remove removes the entry from the cache and returns error if not there
func (c *Cache) Remove(u interface{}) (err error) {
	c.Lock()
	defer c.Unlock()

	val, ok := c.data[u]
	if !ok {
		return fmt.Errorf("Item does not exist")
	}

	// If the type implements Cleanable, Cleanup
	if _, ok := val.value.(Cleanable); ok {
		val.value.(Cleanable).Cleanup()
	}

	delete(c.data, u)

	return nil
}

//Refresh : will parse the cache for expired entries and validate them
//We will be passhing a validation function as argument here
//Details TBD
func (c *Cache) Refresh(d time.Duration) {
	for u := range c.data {
		if time.Since(c.data[u].timestamp) > d {
			// TBD -- Placeholder and lets move one
			newValue := c.refresh(c.data[u].value)
			c.AddOrUpdate(u, newValue)

		}
	}
}

//SizeOf returns the number of elements in the cache
func (c *Cache) SizeOf() int {

	return len(c.data)

}

//LockedModify  locks the data store
func (c *Cache) LockedModify(u interface{}, add func(a, b interface{}) interface{}, increment interface{}) (interface{}, error) {
	c.Lock()
	defer c.Unlock()

	e, ok := c.data[u]
	if !ok {
		return nil, fmt.Errorf("Item not found")
	}

	e.value = add(e.value, increment)
	c.data[u] = e

	return e.value, nil

}

//DumpStore prints the whole data store for debuggin
func (c *Cache) DumpStore() {
	for u := range c.data {
		glog.V(5).Infoln(u, c.data[u])
	}
}
