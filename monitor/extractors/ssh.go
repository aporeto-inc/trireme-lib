package extractors

import (
	"fmt"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
)

// SSHMetadataExtractor is a metadata extractor for ssh.
func SSHMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}

		// This means we send something that is for internal purposes only
		// We add it as it is.
		if strings.HasPrefix(tag, "$") {
			runtimeTags.AppendKeyValue(parts[0], parts[1])
			continue
		}

		runtimeTags.AppendKeyValue("@user:ssh:"+parts[0], parts[1])
	}
	markHdl := cgnetcls.NewMarkAllocator()
	markValue := markHdl.GetMark()
	if markValue == -1 {
		return nil, fmt.Errorf("Unable to allocated mark for %s", event.PUID)
	}
	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(uint64(markValue), 10),
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, event.PUType, options), nil
}
