package dockermonitor

import (
	"sync"

	"github.com/aporeto-inc/trireme-lib/policy"
)

type cache struct {
	// runtimeCache keeps a mapping between a PUID and the corresponding runtime.
	runtimeCache map[string]*policy.PURuntime

	// Lock for the whole cache
	sync.RWMutex
}

func newCache() *cache {
	return &cache{
		runtimeCache: map[string]*policy.PURuntime{},
	}
}

func (c *cache) addOrUpdateRuntime(puid string, runtime *policy.PURuntime) {
	c.Lock()
	defer c.Unlock()

	c.runtimeCache[puid] = runtime
}

func (c *cache) getRuntime(puid string) *policy.PURuntime {
	c.Lock()
	defer c.Unlock()

	runtime, ok := c.runtimeCache[puid]
	if !ok {
		return nil
	}

	return runtime
}

func (c *cache) deleteRuntime(puid string) {
	c.Lock()
	defer c.Unlock()

	delete(c.runtimeCache, puid)
}
