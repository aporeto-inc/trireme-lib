package cnimonitor

import (
	"fmt"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
)

// KubernetesCNIMetadataExtractor is a systemd based metadata extractor
func KubernetesCNIMetadataExtractor(event *rpcmonitor.EventInfo) (*policy.PURuntime, error) {

	if event.Name == "" {
		return nil, fmt.Errorf("EventInfo PU Name is empty")
	}

	if event.PUID == "" {
		return nil, fmt.Errorf("EventInfo PUID is empty")
	}

	runtimeTags := policy.NewTagStore()

	for k, v := range event.Tags {
		runtimeTags.AppendKeyValue("@usr:"+k, v)
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, 1, runtimeTags, runtimeIps, constants.LinuxProcessPU, nil), nil
}

// DockerCNIMetadataExtractor is a systemd based metadata extractor
func DockerCNIMetadataExtractor(event *rpcmonitor.EventInfo) (*policy.PURuntime, error) {

	if event.Name == "" {
		return nil, fmt.Errorf("EventInfo PU Name is empty")
	}

	if event.PUID == "" {
		return nil, fmt.Errorf("EventInfo PUID is empty")
	}

	runtimeTags := policy.NewTagStore()

	for k, v := range event.Tags {
		runtimeTags.AppendKeyValue("@usr:"+k, v)
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, 1, runtimeTags, runtimeIps, constants.LinuxProcessPU, nil), nil
}
