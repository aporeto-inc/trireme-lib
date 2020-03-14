// +build !windows

package kubernetesmonitor

import (
	"sync"

	"go.aporeto.io/trireme-lib/policy"
)

// puidCacheEntry is a Kubernetes entry based on Docker as a key.
// This entry keeps track of the DockerMonitor properties that cannot be queried later on (such as the runtime)
type puidCacheEntry struct {
	// podID is the reference to the Kubernetes pod that this container refers to
	kubeIdentifier string

	// The latest reference to the runtime as received from DockerMonitor
	dockerRuntime policy.RuntimeReader

	// The latest reference to the runtime as received from DockerMonitor
	kubernetesRuntime policy.RuntimeReader
}

// podCacheEntry is a Kubernetes entry based on a Pod as Key. The main goal here is to keep a mapping to all
// existing Dockers PUIDs implementing this pod (as there might be multiple)
type podCacheEntry struct {
	// puIDs us a map containing a link to all the containers currently known to be part of that pod.
	puIDs map[string]bool
}

// Cache is a cache implementation specific to KubernetesMonitor.
// puidCache is centered on Docker and podCache is centered on Kubernetes
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
func (c *cache) updatePUIDCache(podNamespace string, podName string, puID string, dockerRuntime policy.RuntimeReader, kubernetesRuntime policy.RuntimeReader) {
	if podNamespace == "" || podName == "" || puID == "" {
		return
	}

	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)

	puidEntry, ok := c.puidCache[puID]
	if !ok {
		puidEntry = &puidCacheEntry{}
		c.puidCache[puID] = puidEntry
	}
	puidEntry.kubeIdentifier = kubeIdentifier
	puidEntry.dockerRuntime = dockerRuntime
	puidEntry.kubernetesRuntime = kubernetesRuntime

	podEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		podEntry = &podCacheEntry{}
		podEntry.puIDs = map[string]bool{}
		c.podCache[kubeIdentifier] = podEntry
	}
	podEntry.puIDs[puID] = true

}

// deletePUIDCache deletes puid corresponding entries from the cache.
func (c *cache) deletePUIDCache(puID string) {
	c.Lock()
	defer c.Unlock()

	// Remove from pod cache.
	puidEntry, ok := c.puidCache[puID]
	if !ok {
		return
	}
	kubeIdentifier := puidEntry.kubeIdentifier

	podEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		return
	}

	delete(podEntry.puIDs, puID)

	// if no more containers in the pod, delete the podEntry.
	if len(podEntry.puIDs) == 0 {
		delete(c.podCache, kubeIdentifier)
	}

	// delete entry in puidcache
	delete(c.puidCache, puID)
}

// getOrCreatePodFromCache locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) getPUIDsbyPod(podNamespace string, podName string) []string {
	c.RLock()
	defer c.RUnlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)
	podEntry, ok := c.podCache[kubeIdentifier]
	if !ok {
		return []string{}
	}

	return keysFromMap(podEntry.puIDs)
}

// getRuntimeByPUID locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) getDockerRuntimeByPUID(puid string) policy.RuntimeReader {
	c.RLock()
	defer c.RUnlock()

	puidEntry, ok := c.puidCache[puid]
	if !ok {
		return nil
	}

	return puidEntry.dockerRuntime
}

// getRuntimeByPUID locks the cache in order to return the pod cache entry if found, or create it if not found
func (c *cache) getKubernetesRuntimeByPUID(puid string) policy.RuntimeReader {
	c.RLock()
	defer c.RUnlock()

	puidEntry, ok := c.puidCache[puid]
	if !ok {
		return nil
	}

	return puidEntry.kubernetesRuntime
}

// deletePodEntry locks the cache in order to deletes pod cache entry.
func (c *cache) deletePodEntry(podNamespace string, podName string) {
	c.Lock()
	defer c.Unlock()

	kubeIdentifier := kubePodIdentifier(podName, podNamespace)

	delete(c.podCache, kubeIdentifier)
}

// deletePUID locks the cache in order to delete the puid from puidcache.
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
