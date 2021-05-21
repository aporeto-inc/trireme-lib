package dnsproxy

import (
	"sync"
)

// mutexMap
type mutexMap struct {
	// as the mutex map has a map of its own
	// we also need to lock access to this map
	l sync.Mutex
	m map[string]*sync.Mutex
}

// unlocker defines the Unlock mechanism which is returned by the Lock method
type unlocker interface {
	// Unlock releases the lock
	Unlock()
}

// newMutexMap initializes a new map of strings which provide a mutex
func newMutexMap() *mutexMap {
	return &mutexMap{m: map[string]*sync.Mutex{}}
}

// Remove removes an entry from the mutex map
func (m *mutexMap) Remove(entry string) {
	m.l.Lock()
	defer m.l.Unlock()
	delete(m.m, entry)
}

// Lock will gain a lock on `entry`. The caller must call `Unlock` on the returned unlocker when done.
func (m *mutexMap) Lock(entry string) unlocker {
	m.l.Lock()
	e, ok := m.m[entry]
	if !ok {
		m.m[entry] = &sync.Mutex{}
		e = m.m[entry]
	}
	m.l.Unlock()
	e.Lock()
	return e
}
