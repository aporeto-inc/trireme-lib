package extractors

import (
	"debug/elf"
	"fmt"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
	portspec "go.aporeto.io/trireme-lib/utils/portspec"
)

// LinuxMetadataExtractorType is a type of Linux metadata extractors
type LinuxMetadataExtractorType func(event *common.EventInfo) (*policy.PURuntime, error)

// DefaultHostMetadataExtractor is a host specific metadata extractor
func DefaultHostMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	markHdl := cgnetcls.NewMarkAllocator()
	markValue := markHdl.GetMark()
	if markValue == -1 {
		return nil, fmt.Errorf("Unable to allocated mark for %s", event.PUID)
	}
	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(uint64(markValue), 10),
		Services:   event.Services,
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, event.PUType, options), nil
}

// SystemdEventMetadataExtractor is a systemd based metadata extractor
// TODO: Remove OLDTAGS
func SystemdEventMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		key, value := parts[0], parts[1]

		if strings.HasPrefix(key, "@app:linux:") {
			runtimeTags.AppendKeyValue(key, value)
			continue
		}

		runtimeTags.AppendKeyValue("@usr:"+key, value)
	}

	userdata := ProcessInfo(event.PID)

	for _, u := range userdata {
		runtimeTags.AppendKeyValue("@sys:"+u, "true")
		runtimeTags.AppendKeyValue("@app:linux:"+u, "true")
	}

	runtimeTags.AppendKeyValue("@sys:hostname", findFQDN(time.Second))
	runtimeTags.AppendKeyValue("@os:hostname", findFQDN(time.Second))

	options := policy.OptionsType{}
	for index, s := range event.Services {
		if s.Port != 0 && s.Ports == nil {
			if pspec, err := portspec.NewPortSpec(s.Port, s.Port, nil); err == nil {
				event.Services[index].Ports = pspec
				event.Services[index].Port = 0
			} else {
				return nil, fmt.Errorf("Invalid Port Spec %s", err)
			}
		}
	}

	markHdl := cgnetcls.NewMarkAllocator()
	markValue := markHdl.GetMark()
	if markValue == -1 {
		return nil, fmt.Errorf("Unable to allocated mark for %s", event.PUID)
	}
	options.Services = event.Services
	options.UserID, _ = runtimeTags.Get("@usr:originaluser")
	options.CgroupMark = strconv.FormatUint(uint64(markValue), 10)
	options.AutoPort = event.AutoPort

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, event.PUType, &options), nil
}

// ProcessInfo returns all metadata captured by a process
func ProcessInfo(pid int32) []string {
	userdata := []string{}

	p, err := process.NewProcess(pid)
	if err != nil {
		return userdata
	}

	uids, err := p.Uids()
	if err != nil {
		return userdata
	}

	groups, err := p.Gids()
	if err != nil {
		return userdata
	}

	username, err := p.Username()
	if err != nil {
		return userdata
	}

	for _, uid := range uids {
		userdata = append(userdata, "uid:"+strconv.Itoa(int(uid)))
	}

	for _, gid := range groups {
		userdata = append(userdata, "gid:"+strconv.Itoa(int(gid)))
	}

	userdata = append(userdata, "username:"+username)

	userid, err := user.Lookup(username)
	if err != nil {
		return userdata
	}

	gids, err := userid.GroupIds()
	if err != nil {
		return userdata
	}

	for i := 0; i < len(gids); i++ {
		userdata = append(userdata, "gids:"+gids[i])
		group, err := user.LookupGroupId(gids[i])
		if err != nil {
			continue
		}
		userdata = append(userdata, "groups:"+group.Name)
	}

	return userdata
}

// Libs returns the list of dynamic library dependencies of an executable
func Libs(binpath string) []string {
	f, err := elf.Open(binpath)
	if err != nil {
		return []string{}
	}

	libraries, _ := f.ImportedLibraries()
	return libraries
}
