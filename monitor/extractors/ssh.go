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
		if strings.HasPrefix(tag, "$") {
			runtimeTags.AppendKeyValue(parts[0], parts[1])
			continue
		}

		// TODO: Remove OLDTAGS
		runtimeTags.AppendKeyValue("@sys:"+parts[0], parts[1])
		runtimeTags.AppendKeyValue("@app:ssh:"+parts[0], parts[1])
	}

	if event.Name == "" {
		event.Name = event.PUID
	}

	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, common.SSHSessionPU, options), nil
}
