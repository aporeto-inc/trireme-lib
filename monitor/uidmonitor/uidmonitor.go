package uidmonitor

import (
	"fmt"
	"strconv"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
)

//UIDMetadataExtractor -- metadata extractor for uid/gid
func UIDMetadataExtractor(event *rpcmonitor.EventInfo) (*policy.PURuntime, error) {
	if event.Name == "" {
		return nil, fmt.Errorf("EventInfo PUName is empty")
	}
	if event.PUID == "" {
		return nil, fmt.Errorf("EventInfo PUID is empty")
	}

	runtimeTags := policy.NewTagStore()

	for k, v := range event.Tags {
		//runtimeTags.Tags["@usr:"+k] = v
		runtimeTags.AppendKeyValue("@usr:"+k, v)
	}

	//Addd more thing here later
	options := policy.ExtendedMap{
		cgnetcls.PortTag:       "0",
		cgnetcls.CgroupNameTag: event.PUID,
	}

	ports, ok := runtimeTags.Get(cgnetcls.PortTag)
	if ok {
		options[cgnetcls.PortTag] = ports
	}
	user, ok := runtimeTags.Get("@usr:originaluser")
	if ok {
		options["USER"] = user
	}
	options[cgnetcls.CgroupMarkTag] = strconv.FormatUint(cgnetcls.MarkVal(), 10)
	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}
	runtimePID, _ := strconv.Atoi(event.PID)
	return policy.NewPURuntime(event.Name, runtimePID, "", runtimeTags, runtimeIps, constants.LinuxProcessPU, options), nil
}
