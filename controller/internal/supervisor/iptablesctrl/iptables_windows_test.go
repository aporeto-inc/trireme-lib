// +build windows

package iptablesctrl

import (
	"context"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"go.aporeto.io/trireme-lib/controller/internal/windows"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/windows/frontman"
	provider "go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/ipsetmanager"
	"go.aporeto.io/trireme-lib/controller/runtime"
	"go.aporeto.io/trireme-lib/policy"
)

const (
	errInvalidParameter   = syscall.Errno(0xC000000D)
	errInsufficientBuffer = syscall.Errno(122)
)

type abi struct {
	filters    map[string]map[string]bool
	ipsets     map[string][]string
	ipsetByID  map[int]string
	ipsetCount int
}

func (a *abi) FrontmanOpenShared() (uintptr, error) {
	return 1234, nil
}

func (a *abi) GetDestInfo(driverHandle, socket, destInfo uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) ApplyDestHandle(socket, destHandle uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) FreeDestHandle(destHandle uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) NewIpset(driverHandle, name, ipsetType, ipset uintptr) (uintptr, error) {
	if name == 0 || ipsetType == 0 || ipset == 0 {
		return 0, errInvalidParameter
	}
	nameStr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(name))) //nolint:govet
	ipsetPtr := (*int)(unsafe.Pointer(ipset))                                   //nolint:govet
	a.ipsetCount++
	*ipsetPtr = a.ipsetCount
	a.ipsets[nameStr] = make([]string, 0)
	a.ipsetByID[a.ipsetCount] = nameStr
	return 1, nil
}

func (a *abi) GetIpset(driverHandle, name, ipset uintptr) (uintptr, error) {
	if name == 0 || ipset == 0 {
		return 0, errInvalidParameter
	}
	nameStr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(name))) //nolint:govet
	ipsetPtr := (*int)(unsafe.Pointer(ipset))                                   //nolint:govet
	for k, v := range a.ipsetByID {
		if v == nameStr {
			*ipsetPtr = k
			return 1, nil
		}
	}
	return 0, errInvalidParameter
}

func (a *abi) DestroyAllIpsets(driverHandle, prefix uintptr) (uintptr, error) {
	if prefix == 0 {
		return 0, errInvalidParameter
	}
	prefixStr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(prefix))) //nolint:govet
	for k := range a.ipsets {
		if strings.HasPrefix(k, prefixStr) {
			for id, name := range a.ipsetByID {
				if name == k {
					delete(a.ipsetByID, id)
					break
				}
			}
			delete(a.ipsets, k)
		}
	}
	return 1, nil
}

func (a *abi) ListIpsets(driverHandle, ipsetNames, ipsetNamesSize, bytesReturned uintptr) (uintptr, error) {
	if bytesReturned == 0 {
		return 0, errInvalidParameter
	}
	bytesReturnedPtr := (*uint32)(unsafe.Pointer(bytesReturned)) //nolint:govet
	fstr := ""
	for k := range a.ipsets {
		fstr += k + ","
	}
	sizeNeeded := len(fstr) * 2
	if sizeNeeded == 0 {
		*bytesReturnedPtr = 0
		return 1, nil
	}
	if int(ipsetNamesSize) < sizeNeeded {
		*bytesReturnedPtr = uint32(sizeNeeded)
		return 0, errInsufficientBuffer
	}
	if ipsetNames == 0 {
		return 0, errInvalidParameter
	}
	buf := (*[1 << 20]uint16)(unsafe.Pointer(ipsetNames))[: ipsetNamesSize/2 : ipsetNamesSize/2] //nolint:govet
	copy(buf, syscall.StringToUTF16(fstr))                                                       //nolint:staticcheck
	buf[ipsetNamesSize/2-1] = 0
	return 1, nil
}

func (a *abi) IpsetAdd(driverHandle, ipset, entry, timeout uintptr) (uintptr, error) {
	if entry == 0 {
		return 0, errInvalidParameter
	}
	entryStr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(entry))) //nolint:govet
	id := int(ipset)
	name := a.ipsetByID[id]
	entries, ok := a.ipsets[name]
	if !ok {
		return 0, errInvalidParameter
	}
	a.ipsets[name] = append(entries, entryStr)
	return 1, nil
}

func (a *abi) IpsetAddOption(driverHandle, ipset, entry, option, timeout uintptr) (uintptr, error) {
	return a.IpsetAdd(driverHandle, ipset, entry, timeout)
}

func (a *abi) IpsetDelete(driverHandle, ipset, entry uintptr) (uintptr, error) {
	if entry == 0 {
		return 0, errInvalidParameter
	}
	entryStr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(entry))) //nolint:govet
	id := int(ipset)
	name := a.ipsetByID[id]
	entries, ok := a.ipsets[name]
	if !ok {
		return 0, errInvalidParameter
	}
	for i, e := range entries {
		if e == entryStr {
			a.ipsets[name] = append(entries[:i], entries[i+1:]...)
			break
		}
	}
	return 1, nil
}

func (a *abi) IpsetDestroy(driverHandle, ipset uintptr) (uintptr, error) {
	id := int(ipset)
	name := a.ipsetByID[id]
	if _, ok := a.ipsets[name]; !ok {
		return 0, errInvalidParameter
	}
	delete(a.ipsetByID, id)
	delete(a.ipsets, name)
	return 1, nil
}

func (a *abi) IpsetFlush(driverHandle, ipset uintptr) (uintptr, error) {
	id := int(ipset)
	name := a.ipsetByID[id]
	if _, ok := a.ipsets[name]; !ok {
		return 0, errInvalidParameter
	}
	a.ipsets[name] = nil
	return 1, nil
}

func (a *abi) IpsetTest(driverHandle, ipset, entry uintptr) (uintptr, error) {
	if entry == 0 {
		return 0, errInvalidParameter
	}
	entryStr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(entry))) //nolint:govet
	id := int(ipset)
	name := a.ipsetByID[id]
	entries, ok := a.ipsets[name]
	if !ok {
		return 0, errInvalidParameter
	}
	for _, e := range entries {
		if e == entryStr {
			return 1, nil
		}
	}
	// not found
	return 0, nil
}

func (a *abi) PacketFilterStart(frontman, firewallName, receiveCallback, loggingCallback uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) PacketFilterClose() (uintptr, error) {
	return 1, nil
}

func (a *abi) PacketFilterForward(info, packet uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) AppendFilter(driverHandle, outbound, filterName uintptr) (uintptr, error) {
	return a.InsertFilter(driverHandle, outbound, 1000, filterName)
}

func (a *abi) InsertFilter(driverHandle, outbound, priority, filterName uintptr) (uintptr, error) {
	if filterName == 0 {
		return 0, errInvalidParameter
	}
	str := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName))) //nolint:govet
	a.filters[str] = make(map[string]bool)
	return 1, nil
}

func (a *abi) DestroyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	if filterName == 0 {
		return 0, errInvalidParameter
	}
	str := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName))) //nolint:govet
	delete(a.filters, str)
	return 1, nil
}

func (a *abi) EmptyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	if filterName == 0 {
		return 0, errInvalidParameter
	}
	str := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName))) //nolint:govet
	a.filters[str] = make(map[string]bool)
	return 1, nil
}

func (a *abi) GetFilterList(driverHandle, outbound, buffer, bufferSize, bytesReturned uintptr) (uintptr, error) {
	if bytesReturned == 0 {
		return 0, errInvalidParameter
	}
	bytesReturnedPtr := (*uint32)(unsafe.Pointer(bytesReturned)) //nolint:govet
	fstr := ""
	for k := range a.filters {
		fstr += k + ","
	}
	sizeNeeded := len(fstr) * 2
	if sizeNeeded == 0 {
		*bytesReturnedPtr = 0
		return 1, nil
	}
	if int(bufferSize) < sizeNeeded {
		*bytesReturnedPtr = uint32(sizeNeeded)
		return 0, errInsufficientBuffer
	}
	if buffer == 0 {
		return 0, errInvalidParameter
	}
	buf := (*[1 << 20]uint16)(unsafe.Pointer(buffer))[: bufferSize/2 : bufferSize/2] //nolint:govet
	copy(buf, syscall.StringToUTF16(fstr))                                           //nolint:staticcheck
	buf[bufferSize/2-1] = 0
	return 1, nil
}

func (a *abi) AppendFilterCriteria(driverHandle, filterName, criteriaName, ruleSpec, ipsetRuleSpecs, ipsetRuleSpecCount uintptr) (uintptr, error) {
	if filterName == 0 || criteriaName == 0 {
		return 0, errInvalidParameter
	}
	fstr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName)))   //nolint:govet
	cstr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(criteriaName))) //nolint:govet
	m, ok := a.filters[fstr]
	if !ok {
		return 0, errInvalidParameter
	}
	m[cstr] = true
	return 1, nil
}

func (a *abi) DeleteFilterCriteria(driverHandle, filterName, criteriaName uintptr) (uintptr, error) {
	if filterName == 0 || criteriaName == 0 {
		return 0, errInvalidParameter
	}
	fstr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName)))   //nolint:govet
	cstr := windows.WideCharPointerToString((*uint16)(unsafe.Pointer(criteriaName))) //nolint:govet
	m, ok := a.filters[fstr]
	if !ok {
		return 0, errInvalidParameter
	}
	delete(m, cstr)
	return 1, nil
}

func Test_WindowsConfigureRulesV4(t *testing.T) {

	a := &abi{
		filters:   make(map[string]map[string]bool),
		ipsets:    make(map[string][]string),
		ipsetByID: make(map[int]string),
	}
	frontman.Driver = a

	Convey("Given a valid instance", t, func() {

		fq := fqconfig.NewFilterQueueWithDefaults()
		fq.DNSServerAddress = []string{"0.0.0.0/0", "::/0"}
		ips := provider.NewGoIPsetProvider()
		aclmanager := ipsetmanager.CreateIPsetManager(ips, ips)
		impl, err := NewInstance(fq, constants.LocalServer, aclmanager, false, nil)
		So(err, ShouldBeNil)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		err = impl.Run(ctx)
		So(err, ShouldBeNil)

		// check filters
		So(a.filters, ShouldHaveLength, 6)
		So(a.filters, ShouldContainKey, "GlobalRules-OUTPUT")
		So(a.filters, ShouldContainKey, "GlobalRules-INPUT")
		So(a.filters, ShouldContainKey, "HostSvcRules-OUTPUT")
		So(a.filters, ShouldContainKey, "HostSvcRules-INPUT")
		So(a.filters, ShouldContainKey, "HostPU-OUTPUT")
		So(a.filters, ShouldContainKey, "HostPU-INPUT")

		// check ipsets
		So(a.ipsets, ShouldHaveLength, 9)
		So(a.ipsets, ShouldContainKey, "TRI-v4-TargetTCP")
		So(a.ipsets, ShouldContainKey, "TRI-v4-TargetUDP")
		So(a.ipsets, ShouldContainKey, "TRI-v4-Excluded")
		So(a.ipsets, ShouldContainKey, "TRI-v6-TargetTCP")
		So(a.ipsets, ShouldContainKey, "TRI-v6-TargetUDP")
		So(a.ipsets, ShouldContainKey, "TRI-v6-Excluded")
		So(a.ipsets, ShouldContainKey, "TRI-v4-WindowsAllIPs")
		So(a.ipsets, ShouldContainKey, "TRI-v6-WindowsAllIPs")
		So(a.ipsets, ShouldContainKey, "TRI-WindowsDNSServer")
		So(a.ipsets["TRI-v4-WindowsAllIPs"], ShouldContain, "0.0.0.0/0")
		So(a.ipsets["TRI-WindowsDNSServer"], ShouldContain, "0.0.0.0/0")
		So(a.ipsets["TRI-v6-WindowsAllIPs"], ShouldContain, "::/0")

		cfg := &runtime.Configuration{}
		impl.SetTargetNetworks(cfg) //nolint
		So(err, ShouldBeNil)

		puInfo := policy.NewPUInfo("Context", "/ns1", common.HostPU)
		puInfo.Policy = policy.NewPUPolicy("Context", "/ns1", policy.Police, nil, nil, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping)
		puInfo.Runtime = policy.NewPURuntimeWithDefaults()
		puInfo.Runtime.SetPUType(common.HostPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		// configure rules
		err = impl.ConfigureRules(1, "ID", puInfo)
		So(err, ShouldBeNil)

		So(a.filters["GlobalRules-OUTPUT"], ShouldContainKey, "-m set --match-set TRI-v4-Excluded dstIP -j ACCEPT")
		So(a.filters["GlobalRules-INPUT"], ShouldContainKey, "-m set --match-set TRI-v4-Excluded srcIP -j ACCEPT")
		So(a.filters["GlobalRules-INPUT"], ShouldContainKey, "-p udp --sports 53 -m set --match-set TRI-WindowsDNSServer srcIP -j NFQUEUE --queue-force -j MARK 83")
		So(a.filters["HostSvcRules-OUTPUT"], ShouldBeEmpty)
		So(a.filters["HostSvcRules-INPUT"], ShouldBeEmpty)
		So(a.filters["HostPU-OUTPUT"], ShouldContainKey, "-m set --match-set TRI-v4-WindowsAllIPs dstIP -j DROP -j NFLOG --nflog-group 10 --nflog-prefix 1215753766:default:default:10")
		So(a.filters["HostPU-OUTPUT"], ShouldContainKey, "-p tcp -m set --match-set TRI-v4-TargetTCP dstIP -j NFQUEUE -j MARK 4096")
		So(a.filters["HostPU-OUTPUT"], ShouldContainKey, "-p tcp -m set --match-set TRI-v4-TargetTCP dstIP -m set --match-set TRI-v4-Proxy-IDeCFL-dst dstIP,dstPort -j REDIRECT --to-ports 20992")
		So(a.filters["HostPU-OUTPUT"], ShouldContainKey, "-p udp -m set --match-set TRI-v4-TargetUDP dstIP -j NFQUEUE -j MARK 4096")
		So(a.filters["HostPU-INPUT"], ShouldContainKey, "-m set --match-set TRI-v4-WindowsAllIPs srcIP -j DROP -j NFLOG --nflog-group 11 --nflog-prefix 1215753766:default:default:10")
		So(a.filters["HostPU-INPUT"], ShouldContainKey, "-p tcp -m set --match-set TRI-v4-Proxy-IDeCFL-srv dstPort -j REDIRECT --to-ports 20992")
		So(a.filters["HostPU-INPUT"], ShouldContainKey, "-p tcp -m set --match-set TRI-v4-TargetTCP srcIP -j NFQUEUE -j MARK 4096")
		So(a.filters["HostPU-INPUT"], ShouldContainKey, "-p udp -m set --match-set TRI-v4-TargetUDP srcIP -m string --string n30njxq7bmiwr6dtxq --offset 2 -j NFQUEUE -j MARK 4096")

		So(a.ipsets, ShouldContainKey, "TRI-v4-Proxy-IDeCFL-srv")
		So(a.ipsets, ShouldContainKey, "TRI-v4-Proxy-IDeCFL-dst")
	})

}
