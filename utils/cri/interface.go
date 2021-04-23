package cri

import (
	criapi "k8s.io/cri-api/pkg/apis"
	criruntimev1alpha2 "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// ExtendedRuntimeService extends the CRI RuntimeService by some verbose functions that are otherwise inaccessible
type ExtendedRuntimeService interface {
	criapi.RuntimeService
	ContainerStatusVerbose(containerID string) (*criruntimev1alpha2.ContainerStatus, map[string]string, error)
	PodSandboxStatusVerbose(podSandboxID string) (*criruntimev1alpha2.PodSandboxStatus, map[string]string, error)
	StatusVerbose() (*criruntimev1alpha2.RuntimeStatus, map[string]string, error)
}
