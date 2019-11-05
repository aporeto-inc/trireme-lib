// +build windows

package extractors

import (
	"debug/pe"
	"encoding/hex"
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

// WindowsMetadataExtractorType is a type of Windows metadata extractors
type WindowsMetadataExtractorType func(event *common.EventInfo) (*policy.PURuntime, error)

// WindowsServiceEventMetadataExtractor is a windows service based metadata extractor
func WindowsServiceEventMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	userdata := WinProcessInfo(event.PID)

	for _, u := range userdata {
		runtimeTags.AppendKeyValue("@sys:"+u, "true")
		runtimeTags.AppendKeyValue("@app:windows:"+u, "true")
	}

	runtimeTags.AppendKeyValue("@sys:hostname", findFQDN(time.Second))
	runtimeTags.AppendKeyValue("@os:hostname", findFQDN(time.Second))

	if fileMd5, err := ComputeFileMd5(event.Executable); err == nil {
		runtimeTags.AppendKeyValue("@sys:filechecksum", hex.EncodeToString(fileMd5))
		runtimeTags.AppendKeyValue("@app:windows:filechecksum", hex.EncodeToString(fileMd5))
	}

	depends := getDllImports(event.Name)
	for _, lib := range depends {
		runtimeTags.AppendKeyValue("@sys:lib:"+lib, "true")
		runtimeTags.AppendKeyValue("@app:windows:lib:"+lib, "true")
	}

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
	options.Services = event.Services
	options.UserID, _ = runtimeTags.Get("@usr:originaluser")
	options.CgroupMark = strconv.FormatUint(cgnetcls.MarkVal(), 10)
	options.AutoPort = event.AutoPort

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, event.PUType, &options), nil
}

// ProcessInfo returns all metadata captured by a Windows process
func WinProcessInfo(pid int32) []string {
	userdata := []string{}

	p, err := process.NewProcess(pid)
	if err != nil {
		return userdata
	}

	// TODO(windows): do equivalent of uids and gids (using GetNamedSecurityInfo and LookupAccountSid, eg)
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

// getDllImports returns the list of dynamic library dependencies of an executable
func getDllImports(binpath string) []string {
	f, err := pe.Open(binpath)
	if err != nil {
		return []string{}
	}
	libraries, _ := f.ImportedLibraries()
	return libraries
}
