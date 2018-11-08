package extractors

import (
	"crypto/md5"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/policy"
	"go.aporeto.io/trireme-lib/utils/cgnetcls"
	portspec "go.aporeto.io/trireme-lib/utils/portspec"
	"go.uber.org/zap"
)

const (

	// PuType is the type of host svc (network only or otherwise)
	PuType = "$PuType"
	// LinuxPU represents the PU type
	LinuxPU = "LinuxPU"

	// HostModeNetworkPU represents host pu in network only mode.
	HostModeNetworkPU = "HostNetworkPU"

	// HostPU represent host pu in true sense (both incoming and outgoing)
	HostPU = "HostPU"
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

	options := &policy.OptionsType{
		CgroupName: event.PUID,
		CgroupMark: strconv.FormatUint(cgnetcls.MarkVal(), 10),
		Services:   event.Services,
	}

	runtimeIps := policy.ExtendedMap{"bridge": "0.0.0.0/0"}

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, common.LinuxProcessPU, options), nil
}

// SystemdEventMetadataExtractor is a systemd based metadata extractor
func SystemdEventMetadataExtractor(event *common.EventInfo) (*policy.PURuntime, error) {

	runtimeTags := policy.NewTagStore()

	for _, tag := range event.Tags {
		parts := strings.SplitN(tag, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tag: %s", tag)
		}
		runtimeTags.AppendKeyValue("@usr:"+parts[0], parts[1])
	}

	userdata := ProcessInfo(event.PID)

	for _, u := range userdata {
		runtimeTags.AppendKeyValue("@sys:"+u, "true")
	}

	runtimeTags.AppendKeyValue("@sys:hostname", findFQDN(time.Second))

	if fileMd5, err := computeFileMd5(event.Name); err == nil {
		runtimeTags.AppendKeyValue("@sys:filechecksum", hex.EncodeToString(fileMd5))
	}

	depends := libs(event.Name)
	for _, lib := range depends {
		runtimeTags.AppendKeyValue("@sys:lib:"+lib, "true")
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

	return policy.NewPURuntime(event.Name, int(event.PID), "", runtimeTags, runtimeIps, common.LinuxProcessPU, &options), nil
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

// computeFileMd5 computes the Md5 of a file
func computeFileMd5(filePath string) ([]byte, error) {

	var result []byte
	file, err := os.Open(filePath)
	if err != nil {
		return result, err
	}
	defer file.Close() //nolint : errcheck

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return result, err
	}

	return hash.Sum(result), nil
}

func findFQDN(expiration time.Duration) string {

	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	// Try to find FQDN
	globalHostname := make(chan string, 1)
	go func() {
		addrs, err := net.LookupIP(hostname)
		if err != nil {
			globalHostname <- hostname
			return
		}

		for _, addr := range addrs {
			if ipv4 := addr.To4(); ipv4 != nil {
				ip, err := ipv4.MarshalText()
				if err != nil {
					globalHostname <- hostname
					return
				}
				hosts, err := net.LookupAddr(string(ip))
				if err != nil || len(hosts) == 0 {
					globalHostname <- hostname
					return
				}
				fqdn := hosts[0]
				globalHostname <- strings.TrimSuffix(fqdn, ".") // return fqdn without trailing dot
			}
		}
	}()

	// Use OS hostname if we dont hear back in a second
	select {
	case <-time.After(expiration):
		return hostname
	case name := <-globalHostname:
		return name
	}
}

// libs returns the list of dynamic library dependencies of an executable
func libs(binpath string) []string {
	f, err := elf.Open(binpath)
	if err != nil {
		return []string{}
	}
	libraries, _ := f.ImportedLibraries()
	return libraries
}

// policyExtensions retrieves policy extensions. Moving this function from extractor package.
func policyExtensions(runtime policy.RuntimeReader) (extensions policy.ExtendedMap) {

	if runtime == nil {
		return nil
	}

	if runtime.Options().PolicyExtensions == nil {
		return nil
	}

	if extensions, ok := runtime.Options().PolicyExtensions.(policy.ExtendedMap); ok {
		return extensions
	}
	return nil
}

// GetPuType returns puType stored by policy extensions.
func GetPuType(runtime policy.RuntimeReader) string {

	if e := policyExtensions(runtime); e != nil {
		if putype, ok := e.Get(PuType); ok {
			zap.L().Debug("extracted PuType as", zap.String("puType", putype))
			return putype
		}
		return ""
	}
	return ""
}

// IsHostmodePU returns true if puType stored by policy extensions is hostmode PU
func IsHostmodePU(runtime policy.RuntimeReader, mode constants.ModeType) bool {

	if mode != constants.LocalServer {
		return false
	}

	if e := policyExtensions(runtime); e != nil {
		putype, ok := e.Get(PuType)
		zap.L().Debug("extracted PuType as", zap.String("puType", putype))
		return ok && (putype == HostModeNetworkPU || putype == HostPU)

	}
	return false
}

// IsHostPU returns true if puType stored by policy extensions is host PU
func IsHostPU(runtime policy.RuntimeReader, mode constants.ModeType) bool {

	if mode != constants.LocalServer {
		return false
	}

	if e := policyExtensions(runtime); e != nil {
		putype, ok := e.Get(PuType)
		zap.L().Debug("extracted PuType as", zap.String("puType", putype))
		return ok && putype == HostPU

	}
	return false
}
