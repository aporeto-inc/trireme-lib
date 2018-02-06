package extractors

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme-lib/common"
	"github.com/aporeto-inc/trireme-lib/policy"
	"github.com/aporeto-inc/trireme-lib/utils/cgnetcls"
)

// UIDMetadataExtractor is a metadata extractor for uid/gid.
func UIDMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	user, ok := runtimeTags.Get("@usr:user")
	if !ok {
		user = ""
	}

	// TODO: improve with additional information here.
	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
		UserID:     user,
		Services:   event.Services,
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, common.UIDLoginPU, options), nil
}
