package linuxmonitor

import (
	"crypto/md5"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/aporeto-inc/trireme/constants"
	"github.com/aporeto-inc/trireme/monitor/linuxmonitor/cgnetcls"
	"github.com/aporeto-inc/trireme/monitor/rpcmonitor"
	"github.com/aporeto-inc/trireme/policy"
	"github.com/shirou/gopsutil/process"
)

// SystemdRPCMetadataExtractor is a systemd based metadata extractor
func SystemdRPCMetadataExtractor(event *rpcmonitor.EventInfo) (*policy.PURuntime, error) {

	if event.Name == "" {
		return nil, fmt.Errorf("EventInfo PU Name is empty")
	}

	if event.PID == "" {
		return nil, fmt.Errorf("EventInfo PID is empty")
	}

	if event.PUID == "" {
		return nil, fmt.Errorf("EventInfo PUID is empty")
	}

	runtimeTags := policy.NewTagStore()

	for k, v := range event.Tags {
		runtimeTags.AppendKeyValue("@usr:"+k, v)
	}

	userdata := processInfo(event.PID)

	for _, u := range userdata {
		runtimeTags.AppendKeyValue("@sys:"+u, "true")
	}

	runtimeTags.AppendKeyValue("@sys:hostname", findFQFN())

	if fileMd5, err := ComputeMd5(event.Name); err == nil {
		runtimeTags.AppendKeyValue("@sys:filechecksum", hex.EncodeToString(fileMd5))
	}

	depends := libs(event.Name)
	for _, lib := range depends {
		runtimeTags.AppendKeyValue("@sys:lib:"+lib, "true")
	}

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

	runtimePID, err := strconv.Atoi(event.PID)

	if err != nil {
		return nil, fmt.Errorf("PID is invalid: %s", err)
	}

	return policy.NewPURuntime(event.Name, runtimePID, runtimeTags, runtimeIps, constants.LinuxProcessPU, options), nil
}

// ComputeMd5 computes the Md5 of a file
func ComputeMd5(filePath string) ([]byte, error) {
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

func findFQFN() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}

	addrs, err := net.LookupIP(hostname)
	if err != nil {
		return hostname
	}

	for _, addr := range addrs {
		if ipv4 := addr.To4(); ipv4 != nil {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname
			}
			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname
			}
			fqdn := hosts[0]
			return strings.TrimSuffix(fqdn, ".") // return fqdn without trailing dot
		}
	}
	return hostname
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

// processInfo returns all metadata captured by a process
func processInfo(pidString string) []string {
	userdata := []string{}

	pid, err := strconv.Atoi(pidString)
	if err != nil {
		return userdata
	}

	p, err := process.NewProcess(int32(pid))
	if err != nil {
		processes, cerr := cgnetcls.ListCgroupProcesses("/" + pidString)
		if cerr != nil {
			return userdata
		}
		for _, c := range processes {
			pid, _ = strconv.Atoi(c)
			p, _ = process.NewProcess(int32(pid))
			if childRunning, cerr := p.IsRunning(); cerr != nil && childRunning {
				break
			}
		}
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

	return userdata
}
