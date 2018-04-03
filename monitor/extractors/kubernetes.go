package extractors

import (
	"github.com/aporeto-inc/trireme-lib/policy"
	api "k8s.io/api/core/v1"
)

// KubernetesMetadataExtractorType is an extractor function for Kubernetes.
// It takes as parameter a standard Docker runtime and a Pod Kubernetes definition and return a PolicyRuntime
// This extractor also provides an extra boolean parameter that is used as a token to decide if activation is required.
type KubernetesMetadataExtractorType func(runtime policy.RuntimeReader, pod *api.Pod) (*policy.PURuntime, bool, error)

// DefaultKubernetesMetadataExtractor is a default implementation for the medatadata extractor for Kubernetes
func DefaultKubernetesMetadataExtractor(runtime policy.RuntimeReader, pod *api.Pod) (*policy.PURuntime, bool, error) {
	return nil, false, nil
}
