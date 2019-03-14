package extractors

import (
	"context"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"

	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/client"
)

// EventMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo. The EventInfo is generic and is provided over the RPC interface
type EventMetadataExtractor func(*common.EventInfo) (*policy.PURuntime, error)

// PodMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// Kubernetes pod.
type PodMetadataExtractor func(context.Context, client.Client, *corev1.Pod) (*policy.PURuntime, error)
