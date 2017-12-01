package cnimonitor

import (
	"fmt"
	"strings"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor/rpc/eventinfo"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// KubernetesMetadataExtractor is a systemd based metadata extractor
func KubernetesMetadataExtractor(event *eventinfo.EventInfo) (*policy.PURuntime, error) {

	if event.NS == "" {
		return nil, fmt.Errorf("NamespacePath is required when using CNI")
	}

	runtimeTags := policy.NewTagStore()
	for _, tag := range event.Tags {
		parts := strings.Split(tag, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("Invalid Tag")
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, 1, "", runtimeTags, runtimeIps, constants.LinuxProcessPU, nil), nil
}

// DockerMetadataExtractor is a systemd based metadata extractor
func DockerMetadataExtractor(event *eventinfo.EventInfo) (*policy.PURuntime, error) {

	if event.NS == "" {
		return nil, fmt.Errorf("NamespacePath is required when using CNI")
	}

	runtimeTags := policy.NewTagStore()
	for _, tag := range event.Tags {
		parts := strings.Split(tag, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("Invalid Tag")
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, 0, event.NS, runtimeTags, runtimeIps, constants.ContainerPU, nil), nil
}
