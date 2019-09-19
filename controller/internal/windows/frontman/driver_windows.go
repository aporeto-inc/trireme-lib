// +build windows

package frontman

import (
	"fmt"
	"syscall"
)

var (
	driverDll        = syscall.NewLazyDLL("Frontman.dll")
	frontManOpenProc = driverDll.NewProc("FrontmanOpenShared")

	// Frontman procs needed for app proxy. The pattern to follow is
	// - call FrontmanGetDestInfo to get original ip/port
	// - create new proxy socket
	// - call FrontmanApplyDestHandle to update WFP redirect data
	// - connect on the new proxy socket
	// - free native data by calling FrontmanFreeDestHandle
	GetDestInfoProc     = driverDll.NewProc("FrontmanGetDestInfo")
	ApplyDestHandleProc = driverDll.NewProc("FrontmanApplyDestHandle")
	FreeDestHandleProc  = driverDll.NewProc("FrontmanFreeDestHandle")

	NewIpsetProc         = driverDll.NewProc("IpsetProvider_NewIpset")
	GetIpsetProc         = driverDll.NewProc("IpsetProvider_GetIpset")
	DestroyAllIpsetsProc = driverDll.NewProc("IpsetProvider_DestroyAll")
	ListIpsetsProc       = driverDll.NewProc("IpsetProvider_ListIPSets")
	IpsetAddProc         = driverDll.NewProc("Ipset_Add")
	IpsetAddOptionProc   = driverDll.NewProc("Ipset_AddOption")
	IpsetDeleteProc      = driverDll.NewProc("Ipset_Delete")
	IpsetDestroyProc     = driverDll.NewProc("Ipset_Destroy")
	IpsetFlushProc       = driverDll.NewProc("Ipset_Flush")
	IpsetTestProc        = driverDll.NewProc("Ipset_Test")

	PacketFilterStartProc   = driverDll.NewProc("PacketFilterStart")
	PacketFilterCloseProc   = driverDll.NewProc("PacketFilterClose")
	PacketFilterForwardProc = driverDll.NewProc("PacketFilterForwardPacket")

	AppendFilterProc         = driverDll.NewProc("AppendFilter")
	InsertFilterProc         = driverDll.NewProc("InsertFilter")
	DestroyFilterProc        = driverDll.NewProc("DestroyFilter")
	EmptyFilterProc          = driverDll.NewProc("EmptyFilter")
	GetFilterListProc        = driverDll.NewProc("GetFilterList")
	AppendFilterCriteriaProc = driverDll.NewProc("AppendFilterCriteria")
	DeleteFilterCriteriaProc = driverDll.NewProc("DeleteFilterCriteria")
)

const (
	FilterActionAllow = iota + 1
	FilterActionBlock
	FilterActionProxy
	FilterActionNfq
)

type DestInfo struct {
	IpAddr     *uint16 // WCHAR* IPAddress		Destination address allocated and will be free by FrontmanFreeDestHandle
	Port       uint16  // USHORT Port			Destination port
	Outbound   int32   // INT32 Outbound		Whether or not this is an outbound or inbound connection
	ProcessId  uint64  // UINT64 ProcessId		Process id.  Only available for outbound connections
	DestHandle uintptr // LPVOID DestHandle		Handle to memory that must be freed by called ProxyDestConnected when connection is established.
}

type PacketInfo struct {
	Ipv4       uint8
	Protocol   uint8
	Outbound   uint8
	Drop       uint8
	IgnoreFlow uint8
	Reserved1  uint8
	Reserved2  uint8
	Reserved3  uint8
	LocalPort  uint16
	RemotePort uint16
	LocalAddr  [4]uint32
	RemoteAddr [4]uint32
	IfIdx      uint32
	SubIfIdx   uint32
	PacketSize uint32
	Mark       uint32
	StartTime  uint64
	StartTime2 uint64
}

type RuleSpec struct {
	Action       uint8
	Log          uint8
	Protocol     uint8
	NotIpset     uint8
	IpsetDstIp   uint8
	IpsetDstPort uint8
	IpsetSrcIp   uint8
	IpsetSrcPort uint8
	ProxyPort    int16
	Reserved     int16
	SrcPortStart uint16
	SrcPortEnd   uint16
	DstPortStart uint16
	DstPortEnd   uint16
	Mark         uint32
	GroupId      uint32
	IpsetName    uintptr // const wchar_t*
	LogPrefix    uintptr // const wchar_t*
}

func GetDriverHandle() (uintptr, error) {
	driverHandle, _, err := frontManOpenProc.Call()
	if syscall.Handle(driverHandle) == syscall.InvalidHandle {
		return 0, fmt.Errorf("got INVALID_HANDLE_VALUE: %v", err)
	}
	return driverHandle, nil
}
