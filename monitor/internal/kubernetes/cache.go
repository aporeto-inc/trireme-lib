package kubernetesmonitor

import (
	"sync"

	"github.com/aporeto-inc/trireme-lib/policy"
)

type puidCacheEntry struct {
	// podID is the reference to the Kubernetes pod that this container refers to
	kubeIdentifier string

	// The latest reference to the runtime as received from DockerMonitor
	runtime policy.RuntimeReader

	// Lock for the specific entry
	sync.RWMutex
}

type podCacheEntry struct {
	// puIDs us a map containing a link to all the containers currently known to be part of that pod.
	puIDs map[string]bool

	// Lock for the specific entry
	sync.RWMutex
}

// Cache keeps all the state needed for the integration.
type cache struct {
	// popuidCache keeps a mapping between a PUID and the corresponding puidCacheEntry.
	puidCache map[string]*puidCacheEntry

	// podCache keeps a mapping between a POD/Namespace name and the corresponding podCacheEntry.
	podCache map[string]*podCacheEntry

	// Lock for the whole cache
	sync.RWMutex
}

// NewCache initialize a cache
func newCache() *cache {
	return &cache{
		puidCache: map[string]*puidCacheEntry{},
		podCache:  map[string]*podCacheEntry{},
	}
}

func kubePodIdentifier(podName string, podNamespace string) string {
	return podNamespace + "/" + podName
}

// updatePUIDCache updates the cache with an entry coming from a container perspective
func (c *cache) updatePUIDCache(podNamespace string, podName string, puID string, runtime policy.RuntimeReader) {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)

	puidEntry, ok := c.puidCache[puID]
	if !ok {
		puidEntry = &puidCacheEntry{}
		c.puidCache[puID] = puidEntry
	}
	puidEntry.kubeIdentifier = kubeIdentifier
	puidEntry.runtime = runtime

	podEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		podEntry = &podCacheEntry{}
		podEntry.puIDs = map[string]bool{}
		c.podCache[kubeIdentifier] = podEntry
	}
	podEntry.puIDs[puID] = true

}

// getOrCreatePodFromCache locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) getPUIDsbyPod(podNamespace string, podName string) []string {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)
	podEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		return nil
	}

	return keysFromMap(podEntry.puIDs)
}

// getRuntimeByPUID locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) getRuntimeByPUID(puid string) policy.RuntimeReader {
	c.Lock()
	defer c.Unlock()

	puidEntry, ok := c.puidCache[puid]
	if !ok {
		return nil
	}

	return puidEntry.runtime
}

// deletePod locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) deletePodEntry(podNamespace string, podName string) {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)

	delete(c.podCache, kubeIdentifier)
}

// deletePUID locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) deletePUIDEntry(puid string) {
	c.Lock()
	defer c.Unlock()

	delete(c.puidCache, puid)
}

func keysFromMap(m map[string]bool) []string {
	keys := make([]string, len(m))

	i := 0
	for k := range m {
		keys[i] = k
		i++
	}

	return keys
}
