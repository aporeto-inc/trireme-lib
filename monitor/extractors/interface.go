package extractors

import (
	"context"

	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/policy"

	corev1 "k8s.io/api/core/v1"
)

// EventMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// EventInfo. The EventInfo is generic and is provided over the RPC interface
type EventMetadataExtractor func(*common.EventInfo) (*policy.PURuntime, error)

// PodMetadataExtractor is a function used to extract a *policy.PURuntime from a given
// Kubernetes pod. It can furthermore extract more information using the client.
// The 5th argument (bool) indicates if a network namespace should get extracted
type PodMetadataExtractor func(context.Context, *corev1.Pod, string) (*policy.PURuntime, error)

// PodPidsSetMaxProcsProgrammer is a function used to program the pids cgroup of a pod for Trireme.
type PodPidsSetMaxProcsProgrammer func(ctx context.Context, pod *corev1.Pod, maxProcs int) error
