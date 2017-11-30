package rpcmonitor

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme-lib/constants"
	"github.com/aporeto-inc/trireme-lib/monitor/eventinfo"
	"github.com/aporeto-inc/trireme-lib/policy"
)

// DefaultEventMetadataExtractor is a default RPC metadata extractor for testing
func DefaultEventMetadataExtractor(event *eventinfo.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()
	runtimeTags.Tags = event.Tags

	runtimeIps := event.IPs
	runtimePID, err := strconv.Atoi(event.PID)
	if err != nil {
		return nil, fmt.Errorf("PID is invalid: %s", err)
	}

	return policy.NewPURuntime(event.Name, runtimePID, "", runtimeTags, runtimeIps, constants.ContainerPU, nil), nil
}
