package kubernetes

import "github.com/aporeto-inc/trireme-lib/policy"

func isPodContainer(runtime policy.RuntimeReader) (bool, error) {
	return true, nil
}

func consolidateKubernetesTags(runtime policy.RuntimeReader) (*policy.PURuntime, error) {
	return nil, nil
}
