// +build windows

package iptablesctrl

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/common"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	tacls "go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/acls"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/controller/runtime"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
)

const (
	errInvalidParameter   = syscall.Errno(0xC000000D)
	errInsufficientBuffer = syscall.Errno(122)
	errAlreadyExists      = syscall.Errno(183)
)

type abi struct {
	filters       map[string]map[string]bool
	ipsets        map[string][]string
	ipsetByID     map[int]string
	ipsetsNomatch map[string][]string
	ipsetCount    int
	sync.Mutex
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
	a.Lock()
	defer a.Unlock()
	nameStr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(name))) // nolint:govet
	ipsetPtr := (*int)(unsafe.Pointer(ipset))                                    // nolint:govet
	a.ipsetCount++
	*ipsetPtr = a.ipsetCount
	a.ipsets[nameStr] = make([]string, 0)
	a.ipsetsNomatch[nameStr] = make([]string, 0)
	a.ipsetByID[a.ipsetCount] = nameStr
	return 1, nil
}

func (a *abi) GetIpset(driverHandle, name, ipset uintptr) (uintptr, error) {
	if name == 0 || ipset == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	nameStr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(name))) // nolint:govet
	ipsetPtr := (*int)(unsafe.Pointer(ipset))                                    // nolint:govet
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
	a.Lock()
	defer a.Unlock()
	prefixStr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(prefix))) // nolint:govet
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
	a.Lock()
	defer a.Unlock()
	bytesReturnedPtr := (*uint32)(unsafe.Pointer(bytesReturned)) // nolint:govet
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
	buf := (*[1 << 20]uint16)(unsafe.Pointer(ipsetNames))[: ipsetNamesSize/2 : ipsetNamesSize/2] // nolint:govet
	copy(buf, syscall.StringToUTF16(fstr))                                                       // nolint:staticcheck
	buf[ipsetNamesSize/2-1] = 0
	return 1, nil
}

func (a *abi) IpsetAdd(driverHandle, ipset, entry, timeout uintptr) (uintptr, error) {
	return a.IpsetAddOption(driverHandle, ipset, entry, 0, timeout)
}

func (a *abi) IpsetAddOption(driverHandle, ipset, entry, option, timeout uintptr) (uintptr, error) {
	if entry == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	entryStr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(entry))) // nolint:govet
	id := int(ipset)
	name := a.ipsetByID[id]
	entries, ok := a.ipsets[name]
	if !ok {
		return 0, errInvalidParameter
	}
	for _, e := range entries {
		if e == entryStr {
			return 0, errAlreadyExists
		}
	}
	if option != 0 {
		optionStr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(option))) // nolint:govet
		if optionStr == "nomatch" {
			entriesNomatch, ok := a.ipsetsNomatch[name]
			if !ok {
				return 0, errInvalidParameter
			}
			a.ipsetsNomatch[name] = append(entriesNomatch, entryStr)
		}
	}
	a.ipsets[name] = append(entries, entryStr)
	return 1, nil
}

func (a *abi) IpsetDelete(driverHandle, ipset, entry uintptr) (uintptr, error) {
	if entry == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	entryStr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(entry))) // nolint:govet
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
	if entriesNomatch, ok := a.ipsetsNomatch[name]; ok {
		for i, e := range entriesNomatch {
			if e == entryStr {
				a.ipsetsNomatch[name] = append(entriesNomatch[:i], entriesNomatch[i+1:]...)
				break
			}
		}
	}
	return 1, nil
}

func (a *abi) IpsetDestroy(driverHandle, ipset uintptr) (uintptr, error) {
	a.Lock()
	defer a.Unlock()
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
	a.Lock()
	defer a.Unlock()
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
	a.Lock()
	defer a.Unlock()
	entryStr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(entry))) // nolint:govet
	id := int(ipset)
	name := a.ipsetByID[id]
	entries, ok := a.ipsets[name]
	if !ok {
		return 0, errInvalidParameter
	}
	for _, e := range entries {
		// TODO nomatch
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

func (a *abi) AppendFilter(driverHandle, outbound, filterName, isGotoFilter uintptr) (uintptr, error) {
	return a.InsertFilter(driverHandle, outbound, 1000, filterName, isGotoFilter)
}

func (a *abi) InsertFilter(driverHandle, outbound, priority, filterName, isGotoFilter uintptr) (uintptr, error) {
	if filterName == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	str := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName))) // nolint:govet
	a.filters[str] = make(map[string]bool)
	return 1, nil
}

func (a *abi) DestroyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	if filterName == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	str := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName))) // nolint:govet
	delete(a.filters, str)
	return 1, nil
}

func (a *abi) EmptyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	if filterName == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	str := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName))) // nolint:govet
	a.filters[str] = make(map[string]bool)
	return 1, nil
}

func (a *abi) GetFilterList(driverHandle, outbound, buffer, bufferSize, bytesReturned uintptr) (uintptr, error) {
	if bytesReturned == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	bytesReturnedPtr := (*uint32)(unsafe.Pointer(bytesReturned)) // nolint:govet
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
	buf := (*[1 << 20]uint16)(unsafe.Pointer(buffer))[: bufferSize/2 : bufferSize/2] // nolint:govet
	copy(buf, syscall.StringToUTF16(fstr))                                           // nolint:staticcheck
	buf[bufferSize/2-1] = 0
	return 1, nil
}

func (a *abi) AppendFilterCriteria(driverHandle, filterName, criteriaName, ruleSpec, ipsetRuleSpecs, ipsetRuleSpecCount uintptr) (uintptr, error) {
	if filterName == 0 || criteriaName == 0 {
		return 0, errInvalidParameter
	}
	a.Lock()
	defer a.Unlock()
	fstr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName)))   // nolint:govet
	cstr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(criteriaName))) // nolint:govet
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
	a.Lock()
	defer a.Unlock()
	fstr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(filterName)))   // nolint:govet
	cstr := frontman.WideCharPointerToString((*uint16)(unsafe.Pointer(criteriaName))) // nolint:govet
	m, ok := a.filters[fstr]
	if !ok {
		return 0, errInvalidParameter
	}
	delete(m, cstr)
	return 1, nil
}

func (a *abi) ListIpsetsDetail(driverHandle, format, ipsetNames, ipsetNamesSize, bytesReturned uintptr) (uintptr, error) {
	return 1, nil
}

func (a *abi) GetCriteriaList(driverHandle, format, criteriaList, criteriaListSize, bytesReturned uintptr) (uintptr, error) {
	return 1, nil
}

func Test_WindowsNomatchIpsets(t *testing.T) {

	a := &abi{
		filters:       make(map[string]map[string]bool),
		ipsets:        make(map[string][]string),
		ipsetsNomatch: make(map[string][]string),
		ipsetByID:     make(map[int]string),
	}
	frontman.Driver = a

	getEnforcerPID = func() int { return 111 }
	getCnsAgentMgrPID = func() int { return 222 }
	getCnsAgentBootPID = func() int { return 333 }

	Convey("Given a valid instance", t, func() {

		fq := newFilterQueueWithDefaults()
		impl, err := NewInstance(fq, constants.LocalServer, false, nil, "", policy.None)
		So(err, ShouldBeNil)

		err = impl.Run(context.Background())
		So(err, ShouldBeNil)

		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"!2001:db8:1234::/48", "!10.10.10.0/24", "::/0", "!10.0.0.0/8", "10.10.0.0/16", "0.0.0.0/0"},
			UDPTargetNetworks: []string{"!10.10.10.0/24", "10.0.0.0/8"},
			ExcludedNetworks:  []string{"!192.168.56.15/32", "127.0.0.1", "192.168.56.0/24"},
		}
		err = impl.SetTargetNetworks(cfg) // nolint
		So(err, ShouldBeNil)

		So(a.ipsets, ShouldContainKey, "TRI-v4-TargetTCP")
		So(a.ipsetsNomatch["TRI-v4-TargetTCP"], ShouldContain, "10.0.0.0/8")
		So(a.ipsetsNomatch["TRI-v4-TargetTCP"], ShouldContain, "10.10.10.0/24")
		So(a.ipsets["TRI-v4-TargetTCP"], ShouldContain, "10.10.0.0/16")
		So(a.ipsetsNomatch["TRI-v4-TargetTCP"], ShouldNotContain, "10.10.0.0/16")
		So(a.ipsets["TRI-v4-TargetTCP"], ShouldContain, "0.0.0.0/1")
		So(a.ipsets["TRI-v4-TargetTCP"], ShouldContain, "128.0.0.0/1")

		So(a.ipsets, ShouldContainKey, "TRI-v6-TargetTCP")
		So(a.ipsetsNomatch["TRI-v6-TargetTCP"], ShouldContain, "2001:db8:1234::/48")
		So(a.ipsets["TRI-v6-TargetTCP"], ShouldContain, "::/1")
		So(a.ipsets["TRI-v6-TargetTCP"], ShouldContain, "8000::/1")
		So(a.ipsetsNomatch["TRI-v6-TargetTCP"], ShouldNotContain, "::/1")
		So(a.ipsetsNomatch["TRI-v6-TargetTCP"], ShouldNotContain, "8000::/1")

		So(a.ipsets, ShouldContainKey, "TRI-v4-TargetUDP")
		So(a.ipsets["TRI-v4-TargetUDP"], ShouldContain, "10.0.0.0/8")
		So(a.ipsetsNomatch["TRI-v4-TargetUDP"], ShouldNotContain, "10.0.0.0/8")
		So(a.ipsets["TRI-v4-TargetUDP"], ShouldContain, "10.10.10.0/24")
		So(a.ipsetsNomatch["TRI-v4-TargetUDP"], ShouldContain, "10.10.10.0/24")

		So(a.ipsets, ShouldContainKey, "TRI-v4-Excluded")
		So(a.ipsets["TRI-v4-Excluded"], ShouldContain, "127.0.0.1")
		So(a.ipsets["TRI-v4-Excluded"], ShouldContain, "192.168.56.0/24")
		So(a.ipsetsNomatch["TRI-v4-Excluded"], ShouldNotContain, "192.168.56.0/24")
		So(a.ipsets["TRI-v4-Excluded"], ShouldContain, "192.168.56.15/32")
		So(a.ipsetsNomatch["TRI-v4-Excluded"], ShouldContain, "192.168.56.15/32")

		// update target networks
		cfgNew := &runtime.Configuration{
			TCPTargetNetworks: []string{"!10.10.0.0/16", "0.0.0.0/0"},
			UDPTargetNetworks: []string{},
			ExcludedNetworks:  []string{"192.168.56.0/24", "!192.168.56.15/32", "127.0.0.1"},
		}
		err = impl.SetTargetNetworks(cfgNew)
		So(err, ShouldBeNil)

		So(a.ipsets["TRI-v4-TargetTCP"], ShouldNotContain, "10.0.0.0/8")
		So(a.ipsets["TRI-v4-TargetTCP"], ShouldContain, "10.10.0.0/16")
		So(a.ipsetsNomatch["TRI-v4-TargetTCP"], ShouldContain, "10.10.0.0/16")
		So(a.ipsets["TRI-v4-TargetTCP"], ShouldContain, "0.0.0.0/1")
		So(a.ipsets["TRI-v4-TargetTCP"], ShouldContain, "128.0.0.0/1")

		So(a.ipsets["TRI-v4-TargetUDP"], ShouldBeEmpty)

		So(a.ipsets["TRI-v4-Excluded"], ShouldContain, "127.0.0.1")
		So(a.ipsets["TRI-v4-Excluded"], ShouldContain, "192.168.56.0/24")
		So(a.ipsetsNomatch["TRI-v4-Excluded"], ShouldNotContain, "192.168.56.0/24")
		So(a.ipsets["TRI-v4-Excluded"], ShouldContain, "192.168.56.15/32")
		So(a.ipsetsNomatch["TRI-v4-Excluded"], ShouldContain, "192.168.56.15/32")
	})
}

func Test_WindowsNomatchIpsetsInExternalNetworks(t *testing.T) {

	a := &abi{
		filters:       make(map[string]map[string]bool),
		ipsets:        make(map[string][]string),
		ipsetsNomatch: make(map[string][]string),
		ipsetByID:     make(map[int]string),
	}
	frontman.Driver = a

	getEnforcerPID = func() int { return 111 }
	getCnsAgentMgrPID = func() int { return 222 }
	getCnsAgentBootPID = func() int { return 333 }

	Convey("Given a valid instance", t, func() {

		fq := newFilterQueueWithDefaults()
		impl, err := NewInstance(fq, constants.LocalServer, false, nil, "", policy.None)
		So(err, ShouldBeNil)

		err = impl.Run(context.Background())
		So(err, ShouldBeNil)

		cfg := &runtime.Configuration{
			TCPTargetNetworks: []string{"!2001:db8:1234::/48", "!10.10.10.0/24", "::/0", "!10.0.0.0/8", "10.10.0.0/16", "0.0.0.0/0"},
			UDPTargetNetworks: []string{"!10.10.10.0/24", "10.0.0.0/8"},
			ExcludedNetworks:  []string{"!192.168.56.15/32", "127.0.0.1", "192.168.56.0/24"},
		}
		err = impl.SetTargetNetworks(cfg) // nolint
		So(err, ShouldBeNil)

		// Setup external networks
		appACLs := policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"10.0.0.0/8", "!10.0.0.0/16", "!10.0.2.0/24", "10.0.2.7"},
				Ports:     []string{"80"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:    policy.Accept | policy.Log,
					ServiceID: "a1",
					PolicyID:  "123a",
				},
			},
			policy.IPRule{
				Addresses: []string{"::/0", "!2001:db8:1234::/48"},
				Ports:     []string{"80"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:    policy.Accept | policy.Log,
					ServiceID: "a3",
					PolicyID:  "1234a",
				},
			},
		}
		netACLs := policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"0.0.0.0/0", "!10.0.0.0/8", "10.0.0.0/16", "!10.0.2.8"},
				Ports:     []string{"80"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:    policy.Accept | policy.Log,
					ServiceID: "a2",
					PolicyID:  "123b",
				},
			},
		}

		policyRules := policy.NewPUPolicy("Context", "/ns1", policy.Police, appACLs, netACLs, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject|policy.Log, policy.Reject|policy.Log)

		puInfo := policy.NewPUInfo("Context", "/ns1", common.HostPU)
		puInfo.Policy = policyRules
		puInfo.Runtime = policy.NewPURuntimeWithDefaults()
		puInfo.Runtime.SetPUType(common.HostPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		// configure rules
		var iprules policy.IPRuleList
		iprules = append(iprules, puInfo.Policy.ApplicationACLs()...)
		iprules = append(iprules, puInfo.Policy.NetworkACLs()...)
		err = impl.iptv4.ipsetmanager.RegisterExternalNets("pu1", iprules)
		So(err, ShouldBeNil)
		err = impl.iptv6.ipsetmanager.RegisterExternalNets("pu1", iprules)
		So(err, ShouldBeNil)

		err = impl.ConfigureRules(0, "pu1", puInfo)
		So(err, ShouldBeNil)

		// Check ipsets
		setName := impl.iptv4.ipsetmanager.GetACLIPsetsNames(appACLs[0:1])[0]
		So(a.ipsets[setName], ShouldContain, "10.0.0.0/8")
		So(a.ipsets[setName], ShouldContain, "10.0.0.0/16")
		So(a.ipsets[setName], ShouldContain, "10.0.2.0/24")
		So(a.ipsets[setName], ShouldContain, "10.0.2.7")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "10.0.0.0/8")
		So(a.ipsetsNomatch[setName], ShouldContain, "10.0.0.0/16")
		So(a.ipsetsNomatch[setName], ShouldContain, "10.0.2.0/24")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "10.0.2.7")

		setName = impl.iptv6.ipsetmanager.GetACLIPsetsNames(appACLs[1:2])[0]
		So(a.ipsets[setName], ShouldContain, "::/1")
		So(a.ipsets[setName], ShouldContain, "8000::/1")
		So(a.ipsets[setName], ShouldContain, "2001:db8:1234::/48")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "::/1")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "8000::/1")
		So(a.ipsetsNomatch[setName], ShouldContain, "2001:db8:1234::/48")

		setName = impl.iptv4.ipsetmanager.GetACLIPsetsNames(netACLs[0:1])[0]
		So(a.ipsets[setName], ShouldContain, "0.0.0.0/1")
		So(a.ipsets[setName], ShouldContain, "128.0.0.0/1")
		So(a.ipsets[setName], ShouldContain, "10.0.0.0/8")
		So(a.ipsets[setName], ShouldContain, "10.0.0.0/16")
		So(a.ipsets[setName], ShouldContain, "10.0.2.8")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "0.0.0.0/1")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "128.0.0.0/1")
		So(a.ipsetsNomatch[setName], ShouldContain, "10.0.0.0/8")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "10.0.0.0/16")
		So(a.ipsetsNomatch[setName], ShouldContain, "10.0.2.8")

		// Reconfigure external networks
		appACLs = policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"10.0.0.0/8", "!10.0.0.0/16", "10.0.2.0/24", "!10.0.2.7"},
				Ports:     []string{"80"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:    policy.Accept | policy.Log,
					ServiceID: "a1",
					PolicyID:  "123a",
				},
			},
		}
		netACLs = policy.IPRuleList{
			policy.IPRule{
				Addresses: []string{"0.0.0.0/0", "10.0.0.0/8", "!10.0.2.0/24"},
				Ports:     []string{"80"},
				Protocols: []string{constants.TCPProtoNum},
				Policy: &policy.FlowPolicy{
					Action:    policy.Accept | policy.Log,
					ServiceID: "a2",
					PolicyID:  "123b",
				},
			},
		}

		policyRules = policy.NewPUPolicy("Context", "/ns1", policy.Police, appACLs, netACLs, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject|policy.Log, policy.Reject|policy.Log)

		puInfoUpdated := policy.NewPUInfo("Context", "/ns1", common.HostPU)
		puInfoUpdated.Policy = policyRules
		puInfoUpdated.Runtime = policy.NewPURuntimeWithDefaults()
		puInfoUpdated.Runtime.SetPUType(common.HostPU)
		puInfoUpdated.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		// Reconfigure rules
		iprules = nil
		iprules = append(iprules, puInfoUpdated.Policy.ApplicationACLs()...)
		iprules = append(iprules, puInfoUpdated.Policy.NetworkACLs()...)
		err = impl.iptv4.ipsetmanager.RegisterExternalNets("pu1", iprules)
		So(err, ShouldBeNil)

		err = impl.UpdateRules(1, "pu1", puInfoUpdated, puInfo)
		So(err, ShouldBeNil)

		impl.iptv4.ipsetmanager.DestroyUnusedIPsets()

		// Check ipsets again
		setName = impl.iptv4.ipsetmanager.GetACLIPsetsNames(appACLs[0:1])[0]
		So(a.ipsets[setName], ShouldContain, "10.0.0.0/8")
		So(a.ipsets[setName], ShouldContain, "10.0.0.0/16")
		So(a.ipsets[setName], ShouldContain, "10.0.2.0/24")
		So(a.ipsets[setName], ShouldContain, "10.0.2.7")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "10.0.0.0/8")
		So(a.ipsetsNomatch[setName], ShouldContain, "10.0.0.0/16")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "10.0.2.0/24")
		So(a.ipsetsNomatch[setName], ShouldContain, "10.0.2.7")

		setName = impl.iptv4.ipsetmanager.GetACLIPsetsNames(netACLs[0:1])[0]
		So(a.ipsets[setName], ShouldContain, "0.0.0.0/1")
		So(a.ipsets[setName], ShouldContain, "128.0.0.0/1")
		So(a.ipsets[setName], ShouldContain, "10.0.0.0/8")
		So(a.ipsets[setName], ShouldContain, "10.0.2.0/24")
		So(a.ipsets[setName], ShouldNotContain, "10.0.2.8")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "0.0.0.0/1")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "128.0.0.0/1")
		So(a.ipsetsNomatch[setName], ShouldNotContain, "10.0.0.0/8")
		So(a.ipsetsNomatch[setName], ShouldContain, "10.0.2.0/24")

		// Configure and check acl cache
		aclCache := tacls.NewACLCache()
		err = aclCache.AddRuleList(puInfoUpdated.Policy.ApplicationACLs())
		So(err, ShouldBeNil)

		defaultFlowPolicy := &policy.FlowPolicy{Action: policy.Reject | policy.Log, PolicyID: "default", ServiceID: "default"}

		report, _, err := aclCache.GetMatchingAction(net.ParseIP("10.0.2.7"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
		So(err, ShouldNotBeNil)
		So(report.Action, ShouldEqual, policy.Reject|policy.Log)

		report, _, err = aclCache.GetMatchingAction(net.ParseIP("10.0.2.8"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
		So(err, ShouldBeNil)
		So(report.Action, ShouldEqual, policy.Accept|policy.Log)

		report, _, err = aclCache.GetMatchingAction(net.ParseIP("10.0.3.1"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
		So(err, ShouldNotBeNil)
		So(report.Action, ShouldEqual, policy.Reject|policy.Log)

		report, _, err = aclCache.GetMatchingAction(net.ParseIP("10.1.3.1"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
		So(err, ShouldBeNil)
		So(report.Action, ShouldEqual, policy.Accept|policy.Log)

		report, _, err = aclCache.GetMatchingAction(net.ParseIP("11.1.3.1"), 80, packet.IPProtocolTCP, defaultFlowPolicy)
		So(err, ShouldNotBeNil)
		So(report.Action, ShouldEqual, policy.Reject|policy.Log)
	})
}

func newFilterQueueWithDefaults() fqconfig.FilterQueue {
	return fqconfig.NewFilterQueue(0, []string{"0.0.0.0/0", "::/0"})
}

func Test_WindowsConfigureRulesV4(t *testing.T) {

	a := &abi{
		filters:       make(map[string]map[string]bool),
		ipsets:        make(map[string][]string),
		ipsetsNomatch: make(map[string][]string),
		ipsetByID:     make(map[int]string),
	}
	frontman.Driver = a

	getEnforcerPID = func() int { return 111 }
	getCnsAgentMgrPID = func() int { return 222 }
	getCnsAgentBootPID = func() int { return 333 }

	Convey("Given a valid instance", t, func() {

		fq := newFilterQueueWithDefaults()
		impl, err := NewInstance(fq, constants.LocalServer, false, nil, "", policy.None)
		So(err, ShouldBeNil)

		err = impl.Run(context.Background())
		So(err, ShouldBeNil)

		// check filters
		So(a.filters, ShouldHaveLength, 8)
		So(a.filters, ShouldContainKey, "GlobalRules-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "GlobalRules-INPUT-v4")
		So(a.filters, ShouldContainKey, "ProcessRules-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "ProcessRules-INPUT-v4")
		So(a.filters, ShouldContainKey, "HostSvcRules-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "HostSvcRules-INPUT-v4")
		So(a.filters, ShouldContainKey, "HostPU-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "HostPU-INPUT-v4")

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
		So(a.ipsets, ShouldContainKey, "TRI-v4-WindowsDNSServer")
		So(a.ipsets["TRI-v4-WindowsAllIPs"], ShouldContain, "0.0.0.0/0")
		So(a.ipsets["TRI-v4-WindowsDNSServer"], ShouldContain, "0.0.0.0/0")
		So(a.ipsets["TRI-v6-WindowsAllIPs"], ShouldContain, "::/0")

		cfg := &runtime.Configuration{}
		impl.SetTargetNetworks(cfg) // nolint
		So(err, ShouldBeNil)

		policyRules := policy.NewPUPolicy("Context", "/ns1", policy.Police, nil, nil, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject|policy.Log, policy.Reject|policy.Log)

		puInfo := policy.NewPUInfo("Context", "/ns1", common.HostPU)
		puInfo.Policy = policyRules
		puInfo.Runtime = policy.NewPURuntimeWithDefaults()
		puInfo.Runtime.SetPUType(common.HostPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		// configure rules
		err = impl.ConfigureRules(1, "ID", puInfo)
		So(err, ShouldBeNil)

		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldContainKey, "-m set --match-set TRI-v4-Excluded dstIP -j ACCEPT_ONCE")
		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getEnforcerPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldContainKey, "-m set --match-set TRI-v4-Excluded srcIP -j ACCEPT_ONCE")
		So(a.filters["GlobalRules-INPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getEnforcerPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldContainKey, "-p udp --sports 53 -m set --match-set TRI-v4-WindowsDNSServer srcIP -j NFQUEUE_FORCE -j MARK 83")
		So(a.filters["ProcessRules-OUTPUT-v4"], ShouldBeEmpty)
		So(a.filters["ProcessRules-INPUT-v4"], ShouldBeEmpty)
		So(a.filters["HostSvcRules-OUTPUT-v4"], ShouldBeEmpty)
		So(a.filters["HostSvcRules-INPUT-v4"], ShouldBeEmpty)
		So(a.filters["HostPU-INPUT-v4"], ShouldContainKey, "-p tcp -m set --match-set TRI-v4-Proxy-IDeCFL-srv dstPort -j REDIRECT --to-ports 20992")
		So(a.filters["TRI-App-IDtxit7H-1-v4"], ShouldContainKey, "-p tcp --tcp-flags 1,1 -m set --match-set TRI-v4-TargetTCP dstIP -j ACCEPT")
		So(a.filters["TRI-App-IDtxit7H-1-v4"], ShouldContainKey, "-p udp -m set --match-set TRI-v4-TargetUDP dstIP -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-App-IDtxit7H-1-v4"], ShouldContainKey, "-p tcp -m set --match-set TRI-v4-TargetTCP dstIP -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-App-IDtxit7H-1-v4"], ShouldContainKey, "-p tcp --tcp-flags 18,18 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-App-IDtxit7H-1-v4"], ShouldContainKey, "-m set --match-set TRI-v4-WindowsAllIPs dstIP -j NFLOG --nflog-group 10 --nflog-prefix 1215753766:default:default:10")
		So(a.filters["TRI-App-IDtxit7H-1-v4"], ShouldContainKey, "-m set --match-set TRI-v4-WindowsAllIPs dstIP -j DROP -j NFLOG --nflog-group 10 --nflog-prefix 1215753766:default:default:6")
		So(a.filters["TRI-Net-IDtxit7H-1-v4"], ShouldContainKey, "-p tcp --tcp-flags 45,0 --tcp-option 34 -j NFQUEUE MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v4"], ShouldContainKey, "-p udp -m string --string n30njxq7bmiwr6dtxq --offset 4 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v4"], ShouldContainKey, "-p udp -m string --string n30njxq7bmiwr6dtxq --offset 6 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v4"], ShouldContainKey, "-p tcp --tcp-flags 2,0 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v4"], ShouldContainKey, "-p tcp --tcp-flags 18,18 -m set --match-set TRI-v4-TargetTCP srcIP -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v4"], ShouldContainKey, "-m set --match-set TRI-v4-WindowsAllIPs srcIP -j NFLOG --nflog-group 11 --nflog-prefix 1215753766:default:default:10")
		So(a.filters["TRI-Net-IDtxit7H-1-v4"], ShouldContainKey, "-m set --match-set TRI-v4-WindowsAllIPs srcIP -j DROP -j NFLOG --nflog-group 11 --nflog-prefix 1215753766:default:default:6")

		So(a.ipsets, ShouldContainKey, "TRI-v4-Proxy-IDeCFL-srv")
		So(a.ipsets, ShouldContainKey, "TRI-v4-Proxy-IDeCFL-dst")
		So(a.ipsets, ShouldContainKey, "TRI-v4-ProcPort-IDeCFL")

		// configure rules for process wrap
		puInfo = policy.NewPUInfo("Context", "/ns1", common.WindowsProcessPU)
		puInfo.Policy = policyRules
		puInfo.Runtime = policy.NewPURuntimeWithDefaults()
		puInfo.Runtime.SetPUType(common.WindowsProcessPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		err = impl.ConfigureRules(1, "1234", puInfo)
		So(err, ShouldBeNil)

		const pidFilterSubstring = "-m owner --pid-owner 1234 --pid-childrenonly"
		So(len(a.filters["ProcessRules-OUTPUT-v4"]), ShouldNotBeZeroValue)
		So(len(a.filters["ProcessRules-INPUT-v4"]), ShouldNotBeZeroValue)

		for filter := range a.filters {

			if strings.HasPrefix(filter, "ProcessRules") {
				for k := range a.filters["ProcessRules-OUTPUT-v4"] {
					So(k, ShouldContainSubstring, pidFilterSubstring)
				}
				for k := range a.filters["ProcessRules-INPUT-v4"] {
					So(k, ShouldContainSubstring, pidFilterSubstring)
				}
			} else {
				for k := range a.filters[filter] {
					So(k, ShouldNotContainSubstring, pidFilterSubstring)
				}
				for k := range a.filters[filter] {
					So(k, ShouldNotContainSubstring, pidFilterSubstring)
				}
			}
		}
	})

}

func Test_WindowsConfigureRulesV6(t *testing.T) {

	a := &abi{
		filters:       make(map[string]map[string]bool),
		ipsets:        make(map[string][]string),
		ipsetsNomatch: make(map[string][]string),
		ipsetByID:     make(map[int]string),
	}
	frontman.Driver = a

	getEnforcerPID = func() int { return 111 }
	getCnsAgentMgrPID = func() int { return 222 }
	getCnsAgentBootPID = func() int { return 333 }

	Convey("Given a valid instance with ipv6 enabled", t, func() {

		fq := newFilterQueueWithDefaults()
		impl, err := NewInstance(fq, constants.LocalServer, true, nil, "", policy.None)
		So(err, ShouldBeNil)

		err = impl.Run(context.Background())
		So(err, ShouldBeNil)

		// check filters
		So(a.filters, ShouldHaveLength, 16)
		So(a.filters, ShouldContainKey, "GlobalRules-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "GlobalRules-INPUT-v4")
		So(a.filters, ShouldContainKey, "ProcessRules-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "ProcessRules-INPUT-v4")
		So(a.filters, ShouldContainKey, "HostSvcRules-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "HostSvcRules-INPUT-v4")
		So(a.filters, ShouldContainKey, "HostPU-OUTPUT-v4")
		So(a.filters, ShouldContainKey, "HostPU-INPUT-v4")
		So(a.filters, ShouldContainKey, "GlobalRules-OUTPUT-v6")
		So(a.filters, ShouldContainKey, "GlobalRules-INPUT-v6")
		So(a.filters, ShouldContainKey, "ProcessRules-OUTPUT-v6")
		So(a.filters, ShouldContainKey, "ProcessRules-INPUT-v6")
		So(a.filters, ShouldContainKey, "HostSvcRules-OUTPUT-v6")
		So(a.filters, ShouldContainKey, "HostSvcRules-INPUT-v6")
		So(a.filters, ShouldContainKey, "HostPU-OUTPUT-v6")
		So(a.filters, ShouldContainKey, "HostPU-INPUT-v6")

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
		So(a.ipsets, ShouldContainKey, "TRI-v4-WindowsDNSServer")
		So(a.ipsets["TRI-v4-WindowsAllIPs"], ShouldContain, "0.0.0.0/0")
		So(a.ipsets["TRI-v4-WindowsDNSServer"], ShouldContain, "0.0.0.0/0")
		So(a.ipsets["TRI-v6-WindowsAllIPs"], ShouldContain, "::/0")

		cfg := &runtime.Configuration{}
		impl.SetTargetNetworks(cfg) // nolint
		So(err, ShouldBeNil)

		policyRules := policy.NewPUPolicy("Context", "/ns1", policy.Police, nil, nil, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject|policy.Log, policy.Reject|policy.Log)

		puInfo := policy.NewPUInfo("Context", "/ns1", common.HostPU)
		puInfo.Policy = policyRules
		puInfo.Runtime = policy.NewPURuntimeWithDefaults()
		puInfo.Runtime.SetPUType(common.HostPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		// configure rules
		err = impl.ConfigureRules(1, "ID", puInfo)
		So(err, ShouldBeNil)

		So(a.filters["GlobalRules-OUTPUT-v6"], ShouldContainKey, "-m set --match-set TRI-v6-Excluded dstIP -j ACCEPT_ONCE")
		So(a.filters["GlobalRules-OUTPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 133/0 -j ACCEPT")
		So(a.filters["GlobalRules-OUTPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 134/0 -j ACCEPT")
		So(a.filters["GlobalRules-OUTPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 135/0 -j ACCEPT")
		So(a.filters["GlobalRules-OUTPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 136/0 -j ACCEPT")
		So(a.filters["GlobalRules-OUTPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 141/0 -j ACCEPT")
		So(a.filters["GlobalRules-OUTPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 142/0 -j ACCEPT")

		So(a.filters["GlobalRules-INPUT-v6"], ShouldContainKey, "-m set --match-set TRI-v6-Excluded srcIP -j ACCEPT_ONCE")
		So(a.filters["GlobalRules-INPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 133/0 -j ACCEPT")
		So(a.filters["GlobalRules-INPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 134/0 -j ACCEPT")
		So(a.filters["GlobalRules-INPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 135/0 -j ACCEPT")
		So(a.filters["GlobalRules-INPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 136/0 -j ACCEPT")
		So(a.filters["GlobalRules-INPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 141/0 -j ACCEPT")
		So(a.filters["GlobalRules-INPUT-v6"], ShouldContainKey, "-p icmpv6 --icmp-type 142/0 -j ACCEPT")
		So(a.filters["ProcessRules-OUTPUT-v6"], ShouldBeEmpty)
		So(a.filters["ProcessRules-INPUT-v6"], ShouldBeEmpty)
		So(a.filters["HostSvcRules-OUTPUT-v6"], ShouldBeEmpty)
		So(a.filters["HostSvcRules-INPUT-v6"], ShouldBeEmpty)
		So(a.filters["TRI-App-IDtxit7H-1-v6"], ShouldContainKey, "-p tcp --tcp-flags 1,1 -m set --match-set TRI-v6-TargetTCP dstIP -j ACCEPT")
		So(a.filters["TRI-App-IDtxit7H-1-v6"], ShouldContainKey, "-p udp -m set --match-set TRI-v6-TargetUDP dstIP -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-App-IDtxit7H-1-v6"], ShouldContainKey, "-p tcp -m set --match-set TRI-v6-TargetTCP dstIP -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-App-IDtxit7H-1-v6"], ShouldContainKey, "-p tcp --tcp-flags 18,18 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-App-IDtxit7H-1-v6"], ShouldContainKey, "-m set --match-set TRI-v6-WindowsAllIPs dstIP -j NFLOG --nflog-group 10 --nflog-prefix 1215753766:default:default:10")
		So(a.filters["TRI-App-IDtxit7H-1-v6"], ShouldContainKey, "-m set --match-set TRI-v6-WindowsAllIPs dstIP -j DROP -j NFLOG --nflog-group 10 --nflog-prefix 1215753766:default:default:6")
		So(a.filters["TRI-Net-IDtxit7H-1-v6"], ShouldContainKey, "-p udp -m string --string n30njxq7bmiwr6dtxq --offset 4 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v6"], ShouldContainKey, "-p udp -m string --string n30njxq7bmiwr6dtxq --offset 6 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v6"], ShouldContainKey, "-p tcp --tcp-flags 45,0 --tcp-option 34 -j NFQUEUE MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v6"], ShouldContainKey, "-p tcp --tcp-flags 2,0 -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v6"], ShouldContainKey, "-p tcp --tcp-flags 18,18 -m set --match-set TRI-v6-TargetTCP srcIP -j NFQUEUE -j MARK 10")
		So(a.filters["TRI-Net-IDtxit7H-1-v6"], ShouldContainKey, "-m set --match-set TRI-v6-WindowsAllIPs srcIP -j NFLOG --nflog-group 11 --nflog-prefix 1215753766:default:default:10")
		So(a.filters["TRI-Net-IDtxit7H-1-v6"], ShouldContainKey, "-m set --match-set TRI-v6-WindowsAllIPs srcIP -j DROP -j NFLOG --nflog-group 11 --nflog-prefix 1215753766:default:default:6")

		So(a.ipsets, ShouldContainKey, "TRI-v6-Proxy-IDeCFL-srv")
		So(a.ipsets, ShouldContainKey, "TRI-v6-Proxy-IDeCFL-dst")
		So(a.ipsets, ShouldContainKey, "TRI-v6-ProcPort-IDeCFL")
	})

}

func Test_WindowsConfigureRulesManagedByCns(t *testing.T) {

	a := &abi{
		filters:       make(map[string]map[string]bool),
		ipsets:        make(map[string][]string),
		ipsetsNomatch: make(map[string][]string),
		ipsetByID:     make(map[int]string),
	}
	frontman.Driver = a

	getEnforcerPID = func() int { return 111 }

	Convey("Given a valid instance where managed by CNS", t, func() {

		getCnsAgentMgrPID = func() int { return 222 }
		getCnsAgentBootPID = func() int { return 333 }

		fq := newFilterQueueWithDefaults()
		impl, err := NewInstance(fq, constants.LocalServer, false, nil, "", policy.None)
		So(err, ShouldBeNil)

		err = impl.Run(context.Background())
		So(err, ShouldBeNil)

		cfg := &runtime.Configuration{}
		impl.SetTargetNetworks(cfg) // nolint
		So(err, ShouldBeNil)

		policyRules := policy.NewPUPolicy("Context", "/ns1", policy.Police, nil, nil, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject|policy.Log, policy.Reject|policy.Log)

		puInfo := policy.NewPUInfo("Context", "/ns1", common.HostPU)
		puInfo.Policy = policyRules
		puInfo.Runtime = policy.NewPURuntimeWithDefaults()
		puInfo.Runtime.SetPUType(common.HostPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		// configure rules
		err = impl.ConfigureRules(1, "ID", puInfo)
		So(err, ShouldBeNil)

		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getEnforcerPID()))
		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getCnsAgentMgrPID()))
		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d --pid-children -j ACCEPT", getCnsAgentBootPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getEnforcerPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getCnsAgentMgrPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d --pid-children -j ACCEPT", getCnsAgentBootPID()))
	})

	Convey("Given a valid instance where not managed by CNS", t, func() {

		getCnsAgentMgrPID = func() int { return -1 }
		getCnsAgentBootPID = func() int { return -1 }

		fq := newFilterQueueWithDefaults()
		impl, err := NewInstance(fq, constants.LocalServer, false, nil, "", policy.None)
		So(err, ShouldBeNil)

		err = impl.Run(context.Background())
		So(err, ShouldBeNil)

		cfg := &runtime.Configuration{}
		impl.SetTargetNetworks(cfg) // nolint
		So(err, ShouldBeNil)

		policyRules := policy.NewPUPolicy("Context", "/ns1", policy.Police, nil, nil, nil, nil, nil, nil, nil, nil, nil, 20992, 0, nil, nil, []string{}, policy.EnforcerMapping, policy.Reject|policy.Log, policy.Reject|policy.Log)

		puInfo := policy.NewPUInfo("Context", "/ns1", common.HostPU)
		puInfo.Policy = policyRules
		puInfo.Runtime = policy.NewPURuntimeWithDefaults()
		puInfo.Runtime.SetPUType(common.HostPU)
		puInfo.Runtime.SetOptions(policy.OptionsType{
			CgroupMark: "10",
		})

		// configure rules
		err = impl.ConfigureRules(1, "ID", puInfo)
		So(err, ShouldBeNil)

		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getEnforcerPID()))
		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldNotContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getCnsAgentMgrPID()))
		So(a.filters["GlobalRules-OUTPUT-v4"], ShouldNotContainKey, fmt.Sprintf("-m owner --pid-owner %d --pid-children -j ACCEPT", getCnsAgentBootPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getEnforcerPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldNotContainKey, fmt.Sprintf("-m owner --pid-owner %d -j ACCEPT", getCnsAgentMgrPID()))
		So(a.filters["GlobalRules-INPUT-v4"], ShouldNotContainKey, fmt.Sprintf("-m owner --pid-owner %d --pid-children -j ACCEPT", getCnsAgentBootPID()))
	})

}
