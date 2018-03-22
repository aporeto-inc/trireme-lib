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
}

// Cache keeps all the state needed for the integration.
type cache struct {
	// contextIDCache keeps a mapping between a POD/Namespace name and the corresponding contextID from Trireme.
	podCache map[string]podCacheEntry
	sync.RWMutex
}

// NewCache initialize a cache
func newCache() *cache {
	return &cache{
		podCache: map[string]podCacheEntry{},
	}
}

func kubePodIdentifier(podName string, podNamespace string) string {
	return podNamespace + "/" + podName
}
