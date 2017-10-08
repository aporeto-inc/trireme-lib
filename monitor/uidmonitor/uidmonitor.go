package uidmonitor

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
)

//UIDMetadataExtractor -- metadata extractor for uid/gid
func UIDMetadataExtractor(event *rpcmonitor.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.Split(tag, "=")
		if len(parts) != 2 {
			return nil, fmt.Errorf("Invalid Tag")
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	user, ok := runtimeTags.Get("@usr:user")
	if !ok {
		user = ""
	}

	//Addd more thing here later
	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
		UserID:     user,
		Services:   event.Services,
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}
	runtimePID, _ := strconv.Atoi(event.PID)
	return policy.NewPURuntime(event.Name, runtimePID, "", runtimeTags, runtimeIps, constants.LinuxProcessPU, options), nil
}
