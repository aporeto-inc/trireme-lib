package kubernetes

import "github.com/aporeto-inc/trireme-lib/policy"

func (m *KubernetesMonitor) consolidateKubernetesTags(runtime policy.RuntimeReader) (*policy.PURuntime, error) {
	return nil, nil

	m.kubernetesClient.PodLabels()
}

func isPodContainer(runtime policy.RuntimeReader) (bool, error) {
	return true, nil
}
