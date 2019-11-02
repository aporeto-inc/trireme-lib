package dockermonitor

import (
	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/monitor/constants"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.uber.org/zap"
)

// getPausePUID returns puid of pause container.
func getPausePUID(extensions policy.ExtendedMap) string {

	if extensions == nil {
		return ""
	}

	if puid, ok := extensions.Get(constants.DockerHostPUID); ok {
		zap.L().Debug("puid of pause container is", zap.String("puid", puid))
		return puid
	}

	return ""
}

// PolicyExtensions retrieves policy extensions
func policyExtensions(runtime policy.RuntimeReader) (extensions policy.ExtendedMap) {

	if runtime == nil {
		return nil
	}

	if runtime.Options().PolicyExtensions == nil {
		return nil
	}

	if extensions, ok := runtime.Options().PolicyExtensions.(policy.ExtendedMap); ok {
		return extensions
	}
	return nil
}

// IsHostNetworkContainer returns true if container has hostnetwork set
// to true or is linked to container with hostnetwork set to true.
func isHostNetworkContainer(runtime policy.RuntimeReader) bool {

	return runtime.PUType() == common.LinuxProcessPU || (getPausePUID(policyExtensions(runtime)) != "")
}

// IsKubernetesContainer checks if the container is in K8s.
func isKubernetesContainer(labels map[string]string) bool {

	if _, ok := labels[constants.K8sPodNamespace]; ok {
		return true
	}
	return false
}

// KubePodIdentifier returns identifier for K8s pod.
func kubePodIdentifier(labels map[string]string) string {

	if !isKubernetesContainer(labels) {
		return ""
	}
	podName := ""
	podNamespace := ""

	podNamespace, ok := labels[constants.K8sPodNamespace]
	if !ok {
		podNamespace = ""
	}

	podName, ok = labels[constants.K8sPodName]
	if !ok {
		podName = ""
	}

	if podName == "" || podNamespace == "" {
		zap.L().Warn("K8s pod does not have podname/podnamespace labels")
		return ""
	}

	return podNamespace + "/" + podName
}
