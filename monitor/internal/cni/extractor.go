package cnimonitor

import (
	"errors"
	"fmt"
	"strings"

	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/policy"
)

// KubernetesMetadataExtractor is a systemd based metadata extractor
func KubernetesMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	if event.NS == "" {
		return nil, errors.New("namespace path is required when using cni")
	}

	runtimeTags := policy.NewTagStore()
	for _, tag := range event.Tags {
		parts := strings.Split(tag, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, 1, "", runtimeTags, runtimeIps, common.LinuxProcessPU, nil), nil
}

// DockerMetadataExtractor is a systemd based metadata extractor
func DockerMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	if event.NS == "" {
		return nil, errors.New("namespace path is required when using cni")
	}

	runtimeTags := policy.NewTagStore()
	for _, tag := range event.Tags {
		parts := strings.Split(tag, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, 0, event.NS, runtimeTags, runtimeIps, common.ContainerPU, nil), nil
}
