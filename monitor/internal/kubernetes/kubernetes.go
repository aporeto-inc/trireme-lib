package kubernetes

import "github.com/aporeto-inc/trireme-lib/policy"

func (m *KubernetesMonitor) consolidateKubernetesTags(runtime policy.RuntimeReader) (policy.RuntimeReader, error) {
	return runtime, nil
}

func isPodContainer(runtime policy.RuntimeReader) (bool, error) {
	return true, nil
}
