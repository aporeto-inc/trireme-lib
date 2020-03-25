// +build windows

package frontman

import (
	"syscall"
)

// ABI represents the 'application binary interface' to the Frontman dll
type ABI interface {
	FrontmanOpenShared() (uintptr, error)
	GetDestInfo(driverHandle, socket, destInfo uintptr) (uintptr, error)
	ApplyDestHandle(socket, destHandle uintptr) (uintptr, error)
	FreeDestHandle(destHandle uintptr) (uintptr, error)
	NewIpset(driverHandle, name, ipsetType, ipset uintptr) (uintptr, error)
	GetIpset(driverHandle, name, ipset uintptr) (uintptr, error)
	DestroyAllIpsets(driverHandle, prefix uintptr) (uintptr, error)
	ListIpsets(driverHandle, ipsetNames, ipsetNamesSize, bytesReturned uintptr) (uintptr, error)
	ListIpsetsDetail(driverHandle, format, ipsetNames, ipsetNamesSize, bytesReturned uintptr) (uintptr, error)
	IpsetAdd(driverHandle, ipset, entry, timeout uintptr) (uintptr, error)
	IpsetAddOption(driverHandle, ipset, entry, option, timeout uintptr) (uintptr, error)
	IpsetDelete(driverHandle, ipset, entry uintptr) (uintptr, error)
	IpsetDestroy(driverHandle, ipset uintptr) (uintptr, error)
	IpsetFlush(driverHandle, ipset uintptr) (uintptr, error)
	IpsetTest(driverHandle, ipset, entry uintptr) (uintptr, error)
	PacketFilterStart(frontman, firewallName, receiveCallback, loggingCallback uintptr) (uintptr, error)
	PacketFilterClose() (uintptr, error)
	PacketFilterForward(info, packet uintptr) (uintptr, error)
	AppendFilter(driverHandle, outbound, filterName uintptr) (uintptr, error)
	InsertFilter(driverHandle, outbound, priority, filterName uintptr) (uintptr, error)
	DestroyFilter(driverHandle, filterName uintptr) (uintptr, error)
	EmptyFilter(driverHandle, filterName uintptr) (uintptr, error)
	GetFilterList(driverHandle, outbound, buffer, bufferSize, bytesReturned uintptr) (uintptr, error)
	AppendFilterCriteria(driverHandle, filterName, criteriaName, ruleSpec, ipsetRuleSpecs, ipsetRuleSpecCount uintptr) (uintptr, error)
	DeleteFilterCriteria(driverHandle, filterName, criteriaName uintptr) (uintptr, error)
	GetCriteriaList(driverHandle, format, criteriaList, criteriaListSize, bytesReturned uintptr) (uintptr, error)
}

type driver struct {
}

// Driver is actually the concrete calls into the Frontman dll, which call into the driver
var Driver = ABI(&driver{})

func (d *driver) FrontmanOpenShared() (uintptr, error) {
	ret, _, err := frontManOpenProc.Call()
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) GetDestInfo(driverHandle, socket, destInfo uintptr) (uintptr, error) {
	ret, _, err := getDestInfoProc.Call(driverHandle, socket, destInfo)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) ApplyDestHandle(socket, destHandle uintptr) (uintptr, error) {
	ret, _, err := applyDestHandleProc.Call(socket, destHandle)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) FreeDestHandle(destHandle uintptr) (uintptr, error) {
	ret, _, err := freeDestHandleProc.Call(destHandle)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) NewIpset(driverHandle, name, ipsetType, ipset uintptr) (uintptr, error) {
	ret, _, err := newIpsetProc.Call(driverHandle, name, ipsetType, ipset)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) GetIpset(driverHandle, name, ipset uintptr) (uintptr, error) {
	ret, _, err := getIpsetProc.Call(driverHandle, name, ipset)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) DestroyAllIpsets(driverHandle, prefix uintptr) (uintptr, error) {
	ret, _, err := destroyAllIpsetsProc.Call(driverHandle, prefix)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) ListIpsets(driverHandle, ipsetNames, ipsetNamesSize, bytesReturned uintptr) (uintptr, error) {
	ret, _, err := listIpsetsProc.Call(driverHandle, ipsetNames, ipsetNamesSize, bytesReturned)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) ListIpsetsDetail(driverHandle, format, ipsetNames, ipsetNamesSize, bytesReturned uintptr) (uintptr, error) {
	ret, _, err := listIpsetsDetailProc.Call(driverHandle, format, ipsetNames, ipsetNamesSize, bytesReturned)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) IpsetAdd(driverHandle, ipset, entry, timeout uintptr) (uintptr, error) {
	ret, _, err := ipsetAddProc.Call(driverHandle, ipset, entry, timeout)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) IpsetAddOption(driverHandle, ipset, entry, option, timeout uintptr) (uintptr, error) {
	ret, _, err := ipsetAddOptionProc.Call(driverHandle, ipset, entry, option, timeout)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) IpsetDelete(driverHandle, ipset, entry uintptr) (uintptr, error) {
	ret, _, err := ipsetDeleteProc.Call(driverHandle, ipset, entry)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) IpsetDestroy(driverHandle, ipset uintptr) (uintptr, error) {
	ret, _, err := ipsetDestroyProc.Call(driverHandle, ipset)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) IpsetFlush(driverHandle, ipset uintptr) (uintptr, error) {
	ret, _, err := ipsetFlushProc.Call(driverHandle, ipset)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) IpsetTest(driverHandle, ipset, entry uintptr) (uintptr, error) {
	ret, _, err := ipsetTestProc.Call(driverHandle, ipset, entry)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) PacketFilterStart(frontman, firewallName, receiveCallback, loggingCallback uintptr) (uintptr, error) {
	ret, _, err := packetFilterStartProc.Call(frontman, firewallName, receiveCallback, loggingCallback)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) PacketFilterClose() (uintptr, error) {
	ret, _, err := packetFilterCloseProc.Call()
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) PacketFilterForward(info, packet uintptr) (uintptr, error) {
	ret, _, err := packetFilterForwardProc.Call(info, packet)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) AppendFilter(driverHandle, outbound, filterName uintptr) (uintptr, error) {
	ret, _, err := appendFilterProc.Call(driverHandle, outbound, filterName)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) InsertFilter(driverHandle, outbound, priority, filterName uintptr) (uintptr, error) {
	ret, _, err := insertFilterProc.Call(driverHandle, outbound, priority, filterName)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) DestroyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	ret, _, err := destroyFilterProc.Call(driverHandle, filterName)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) EmptyFilter(driverHandle, filterName uintptr) (uintptr, error) {
	ret, _, err := emptyFilterProc.Call(driverHandle, filterName)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) GetFilterList(driverHandle, outbound, buffer, bufferSize, bytesReturned uintptr) (uintptr, error) {
	ret, _, err := getFilterListProc.Call(driverHandle, outbound, buffer, bufferSize, bytesReturned)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) AppendFilterCriteria(driverHandle, filterName, criteriaName, ruleSpec, ipsetRuleSpecs, ipsetRuleSpecCount uintptr) (uintptr, error) {
	ret, _, err := appendFilterCriteriaProc.Call(driverHandle, filterName, criteriaName, ruleSpec, ipsetRuleSpecs, ipsetRuleSpecCount)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) DeleteFilterCriteria(driverHandle, filterName, criteriaName uintptr) (uintptr, error) {
	ret, _, err := deleteFilterCriteriaProc.Call(driverHandle, filterName, criteriaName)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

func (d *driver) GetCriteriaList(driverHandle, format, criteriaList, criteriaListSize, bytesReturned uintptr) (uintptr, error) {
	ret, _, err := getCriteriaListProc.Call(driverHandle, format, criteriaList, criteriaListSize, bytesReturned)
	if err == syscall.Errno(0) {
		err = nil
	}
	return ret, err
}

// Frontman.dll procs to be called from Go
var (
	driverDll        = syscall.NewLazyDLL("Frontman.dll")
	frontManOpenProc = driverDll.NewProc("FrontmanOpenShared")

	// Frontman procs needed for app proxy. The pattern to follow is
	// - call FrontmanGetDestInfo to get original ip/port
	// - create new proxy socket
	// - call FrontmanApplyDestHandle to update WFP redirect data
	// - connect on the new proxy socket
	// - free kernel data by calling FrontmanFreeDestHandle
	getDestInfoProc     = driverDll.NewProc("FrontmanGetDestInfo")
	applyDestHandleProc = driverDll.NewProc("FrontmanApplyDestHandle")
	freeDestHandleProc  = driverDll.NewProc("FrontmanFreeDestHandle")

	newIpsetProc         = driverDll.NewProc("IpsetProvider_NewIpset")
	getIpsetProc         = driverDll.NewProc("IpsetProvider_GetIpset")
	destroyAllIpsetsProc = driverDll.NewProc("IpsetProvider_DestroyAll")
	listIpsetsProc       = driverDll.NewProc("IpsetProvider_ListIPSets")
	listIpsetsDetailProc = driverDll.NewProc("IpsetProvider_ListIPSetsDetail")
	ipsetAddProc         = driverDll.NewProc("Ipset_Add")
	ipsetAddOptionProc   = driverDll.NewProc("Ipset_AddOption")
	ipsetDeleteProc      = driverDll.NewProc("Ipset_Delete")
	ipsetDestroyProc     = driverDll.NewProc("Ipset_Destroy")
	ipsetFlushProc       = driverDll.NewProc("Ipset_Flush")
	ipsetTestProc        = driverDll.NewProc("Ipset_Test")

	packetFilterStartProc   = driverDll.NewProc("PacketFilterStart")
	packetFilterCloseProc   = driverDll.NewProc("PacketFilterClose")
	packetFilterForwardProc = driverDll.NewProc("PacketFilterForwardPacket")

	appendFilterProc         = driverDll.NewProc("AppendFilter")
	insertFilterProc         = driverDll.NewProc("InsertFilter")
	destroyFilterProc        = driverDll.NewProc("DestroyFilter")
	emptyFilterProc          = driverDll.NewProc("EmptyFilter")
	getFilterListProc        = driverDll.NewProc("GetFilterList")
	appendFilterCriteriaProc = driverDll.NewProc("AppendFilterCriteria")
	deleteFilterCriteriaProc = driverDll.NewProc("DeleteFilterCriteria")
	getCriteriaListProc      = driverDll.NewProc("GetCriteriaList")
)

// See frontmanIO.h for #defines
const (
	FilterActionContinue = iota
	FilterActionAllow
	FilterActionBlock
	FilterActionProxy
	FilterActionNfq
	FilterActionForceNfq
)

// See frontmanIO.h for #defines
const (
	BytesMatchStartIPHeader = iota + 1
	BytesMatchStartProtocolHeader
	BytesMatchStartPayload
)

// See Filter_set.h
const (
	CriteriaListFormatString = iota + 1
	CriteriaListFormatJson
)

// See Ipset.h
const (
	IpsetsDetailFormatString = iota + 1
	IpsetsDetailFormatJson
)

// DestInfo mirrors frontman's DEST_INFO struct
type DestInfo struct {
	IPAddr     *uint16 // WCHAR* IPAddress		Destination address allocated and will be free by FrontmanFreeDestHandle
	Port       uint16  // USHORT Port			Destination port
	Outbound   int32   // INT32 Outbound		Whether or not this is an outbound or inbound connection
	ProcessID  uint64  // UINT64 ProcessId		Process id.  Only available for outbound connections
	DestHandle uintptr // LPVOID DestHandle		Handle to memory that must be freed by called ProxyDestConnected when connection is established.
}

// PacketInfo mirrors frontman's FRONTMAN_PACKET_INFO struct
type PacketInfo struct {
	Ipv4                         uint8
	Protocol                     uint8
	Outbound                     uint8
	Drop                         uint8
	IgnoreFlow                   uint8
	Reserved1                    uint8
	Reserved2                    uint8
	Reserved3                    uint8
	LocalPort                    uint16
	RemotePort                   uint16
	LocalAddr                    [4]uint32
	RemoteAddr                   [4]uint32
	IfIdx                        uint32
	SubIfIdx                     uint32
	PacketSize                   uint32
	Mark                         uint32
	StartTimeReceivedFromNetwork uint64
	StartTimeSentToUserLand      uint64
}

// LogPacketInfo mirrors frontman's FRONTMAN_LOG_PACKET_INFO struct
type LogPacketInfo struct {
	Ipv4       uint8
	Protocol   uint8
	Outbound   uint8
	Reserved1  uint8
	LocalPort  uint16
	RemotePort uint16
	LocalAddr  [4]uint32
	RemoteAddr [4]uint32
	PacketSize uint32
	GroupID    uint32
	LogPrefix  [64]uint16
}

// IpsetRuleSpec mirrors frontman's IPSET_RULE_SPEC struct
type IpsetRuleSpec struct {
	NotIpset     uint8
	IpsetDstIP   uint8
	IpsetDstPort uint8
	IpsetSrcIP   uint8
	IpsetSrcPort uint8
	Reserved1    uint8
	Reserved2    uint8
	Reserved3    uint8
	IpsetName    uintptr // const wchar_t*
}

// PortRange mirrors frontman's PORT_RANGE struct
type PortRange struct {
	PortStart uint16
	PortEnd   uint16
}

// RuleSpec mirrors frontman's RULE_SPEC struct
type RuleSpec struct {
	Action            uint8
	Log               uint8
	Protocol          uint8
	ProtocolSpecified uint8
	IcmpType          uint8
	IcmpTypeSpecified uint8
	IcmpCode          uint8
	IcmpCodeSpecified uint8
	AleAuthConnect    uint8 // not used by us
	Reserved1         uint8
	Reserved2         uint8
	Reserved3         uint8
	ProxyPort         uint16
	BytesMatchStart   int16 // See frontmanIO.h for BYTESMATCH defines.
	BytesMatchOffset  int32
	BytesMatchSize    int32
	BytesMatch        *byte
	Mark              uint32
	GroupID           uint32
	SrcPortCount      int32
	DstPortCount      int32
	SrcPorts          *PortRange
	DstPorts          *PortRange
	LogPrefix         uintptr // const wchar_t*
	Application       uintptr // const wchar_t*
}
