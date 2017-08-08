package cnimonitor

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
)

// CNIMetadataExtractor is a systemd based metadata extractor
func CNIMetadataExtractor(event *rpcmonitor.EventInfo) (*policy.PURuntime, error) {

	if event.Name == "" {
		return nil, fmt.Errorf("EventInfo PU Name is empty")
	}

	if event.PID == "" {
		return nil, fmt.Errorf("EventInfo PID is empty")
	}

	if event.PUID == "" {
		return nil, fmt.Errorf("EventInfo PUID is empty")
	}

	runtimeTags := policy.NewTagStore()

	for k, v := range event.Tags {
		runtimeTags.AppendKeyValue("@usr:"+k, v)
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	runtimePID, err := strconv.Atoi(event.PID)

	if err != nil {
		return nil, fmt.Errorf("PID is invalid: %s", err)
	}

	return policy.NewPURuntime(event.Name, runtimePID, runtimeTags, runtimeIps, constants.LinuxProcessPU, nil), nil
}
