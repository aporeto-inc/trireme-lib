package kubernetesmonitor

import (
	"sync"

	"github.com/aporeto-inc/trireme-lib/policy"
	api "k8s.io/api/core/v1"
)

type podCacheEntry struct {
	contextID string
	// The latest reference to the runtime as received from DockerMonitor
	runtime policy.RuntimeReader
	// The latest known reference to the pod received from Kubernetes API
	pod *api.Pod

	// Lock for the specific entry
	sync.RWMutex
}

// Cache keeps all the state needed for the integration.
type cache struct {
	// contextIDCache keeps a mapping between a POD/Namespace name and the corresponding contextID from Trireme.
	podCache map[string]*podCacheEntry

	// Lock for the whole cache
	sync.RWMutex
}

// NewCache initialize a cache
func newCache() *cache {
	return &cache{
		podCache: map[string]*podCacheEntry{},
	}
}

func kubePodIdentifier(podName string, podNamespace string) string {
	return podNamespace + "/" + podName
}

// getOrCreatePodFromCache locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) getOrCreatePodFromCache(podNamespace string, podName string) *podCacheEntry {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)
	cacheEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		cacheEntry = &podCacheEntry{}
		c.podCache[kubeIdentifier] = cacheEntry
	}
	return cacheEntry
}
