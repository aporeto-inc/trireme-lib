package extractors

import (
	"fmt"
	"strconv"
	"strings"

	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/policy"
	"go.aporeto.io/trireme-lib/v11/utils/cgnetcls"
)

// UIDMetadataExtractor is a metadata extractor for uid/gid.
func UIDMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		// TODO: Remove OLDTAGS
		runtimeTags.AppendKeyValue("@sys:"+parts[0], parts[1])
		runtimeTags.AppendKeyValue("@app:linux:"+parts[0], parts[1])
	}

	if event.Name == "" {
		event.Name = event.PUID
	}

	// TODO: improve with additional information here.
	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
		UserID:     event.PUID,
		Services:   event.Services,
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, common.UIDLoginPU, options), nil
}
