package kubernetesmonitor

import (
	"fmt"
	"sync"

	"github.com/aporeto-inc/trireme-lib/policy"
	api "k8s.io/api/core/v1"
)

type podCacheEntry struct {
	puIDs map[string]bool
	// The latest reference to the runtime as received from DockerMonitor
	runtime policy.RuntimeReader
	// The latest known reference to the pod received from Kubernetes API
	pod *api.Pod

	// Lock for the specific entry
	sync.RWMutex
}

// Cache keeps all the state needed for the integration.
type cache struct {
	// podCache keeps a mapping between a POD/Namespace name and the corresponding podCacheEntry.
	podCache map[string]*podCacheEntry

	// popuidCache keeps a mapping between a PUID and the Kubernetes key
	puidCache map[string]string

	// Lock for the whole cache
	sync.RWMutex
}

// NewCache initialize a cache
func newCache() *cache {
	return &cache{
		podCache:  map[string]*podCacheEntry{},
		puidCache: map[string]string{},
	}
}

func kubePodIdentifier(podName string, podNamespace string) string {
	return podNamespace + "/" + podName
}

// createPodEntry locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) createPodEntry(podNamespace string, podName string, puID string, runtime policy.RuntimeReader) *podCacheEntry {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)
	cacheEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		cacheEntry = &podCacheEntry{}
		c.podCache[kubeIdentifier] = cacheEntry
	}
	cacheEntry.puIDs = map[string]bool{}
	cacheEntry.runtime = runtime

	c.puidCache[puID] = kubeIdentifier

	return cacheEntry
}

func (c *cache) updatePodEntry(podNamespace string, podName string, pod *api.Pod) (*podCacheEntry, error) {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)
	cacheEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		cacheEntry = &podCacheEntry{}
		c.podCache[kubeIdentifier] = cacheEntry
	}

	cacheEntry.Lock()
	defer cacheEntry.Unlock()

	cacheEntry.pod = pod

	return cacheEntry, nil
}

// getOrCreatePodFromCache locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) getPodByPUID(puid string) (*podCacheEntry, error) {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier, ok := c.puidCache[puid]
	if !ok {
		return nil, fmt.Errorf("puid not found in cache")
	}
	cacheEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		return nil, fmt.Errorf("inconsistent cache, pod not found")
	}
	return cacheEntry, nil
}

// getOrCreatePodFromCache locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) deletePodByKube(podNamespace string, podName string) error {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)

	delete(c.podCache, kubeIdentifier)

	return nil
}

// getOrCreatePodFromCache locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) deletePodByPUID(puid string) error {
	c.Lock()
	defer c.Unlock()

	delete(c.puidCache, puid)

	return nil
}
