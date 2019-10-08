// +build windows

package frontman

import (
	"testing"
	"unsafe"

	. "github.com/smartystreets/goconvey/convey"

	"go.aporeto.io/windows/go-frontman/abi"
)

func TestFrontmanStructLayout(t *testing.T) {

	Convey("Given a Frontman PDB", t, func() {

		pdb, err := abi.FindFrontmanPdb()
		So(err, ShouldBeNil)

		Convey("The layout of DestInfo and DEST_INFO should be the same", func() {
			layout, err := pdb.GetStructLayout("_DEST_INFO")
			So(err, ShouldBeNil)
			So(unsafe.Sizeof(DestInfo{}), ShouldEqual, layout.Size)
			// WCHAR* IPAddress
			index := 0
			So("IPAddress", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(DestInfo{}.IpAddr), ShouldEqual, layout.Members[index].Offset)
			// USHORT Port
			index++
			So("Port", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(DestInfo{}.Port), ShouldEqual, layout.Members[index].Offset)
			// INT32 Outbound
			index++
			So("Outbound", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(DestInfo{}.Outbound), ShouldEqual, layout.Members[index].Offset)
			// UINT64 ProcessId
			index++
			So("ProcessId", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(DestInfo{}.ProcessId), ShouldEqual, layout.Members[index].Offset)
			// LPVOID DestHandle
			index++
			So("DestHandle", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(DestInfo{}.DestHandle), ShouldEqual, layout.Members[index].Offset)
		})

		Convey("The layout of PacketInfo and FRONTMAN_PACKET_INFO should be the same", func() {
			layout, err := pdb.GetStructLayout("FRONTMAN_PACKET_INFO")
			So(err, ShouldBeNil)
			So(unsafe.Sizeof(PacketInfo{}), ShouldEqual, layout.Size)
			// UINT8 Ipv4
			index := 0
			So("Ipv4", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.Ipv4), ShouldEqual, layout.Members[index].Offset)
			// UINT8 Protocol
			index++
			So("Protocol", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.Protocol), ShouldEqual, layout.Members[index].Offset)
			// UINT8 Outbound
			index++
			So("Outbound", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.Outbound), ShouldEqual, layout.Members[index].Offset)
			// UINT8 Drop
			index++
			So("Drop", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.Drop), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IngoreFlow [sic]
			index++
			So("IngoreFlow", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.IgnoreFlow), ShouldEqual, layout.Members[index].Offset)
			// skip reserved
			index += 3
			// UINT16 LocalPort
			index++
			So("LocalPort", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.LocalPort), ShouldEqual, layout.Members[index].Offset)
			// UINT16 RemotePort
			index++
			So("RemotePort", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.RemotePort), ShouldEqual, layout.Members[index].Offset)
			// UINT32 LocalAddr[4]
			index++
			So("LocalAddr", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.LocalAddr), ShouldEqual, layout.Members[index].Offset)
			// UINT32 RemoteAddr[4]
			index++
			So("RemoteAddr", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.RemoteAddr), ShouldEqual, layout.Members[index].Offset)
			// UINT32 IfIdx
			index++
			So("IfIdx", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.IfIdx), ShouldEqual, layout.Members[index].Offset)
			// UINT32 SubIfIdx
			index++
			So("SubIfIdx", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.SubIfIdx), ShouldEqual, layout.Members[index].Offset)
			// UINT32 PacketSize
			index++
			So("PacketSize", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.PacketSize), ShouldEqual, layout.Members[index].Offset)
			// UINT32 Mark
			index++
			So("Mark", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.Mark), ShouldEqual, layout.Members[index].Offset)
			// UINT64 StartTimeReceivedFromNetwork
			index++
			So("StartTimeReceivedFromNetwork", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.StartTimeReceivedFromNetwork), ShouldEqual, layout.Members[index].Offset)
			// UINT64 StartTimeSentToUserLand
			index++
			So("StartTimeSentToUserLand", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(PacketInfo{}.StartTimeSentToUserLand), ShouldEqual, layout.Members[index].Offset)
		})

		Convey("The layout of RuleSpec and RULE_SPEC should be the same", func() {
			layout, err := pdb.GetStructLayout("RULE_SPEC")
			So(err, ShouldBeNil)
			So(unsafe.Sizeof(RuleSpec{}), ShouldEqual, layout.Size)
			// UINT8 Action
			index := 0
			So("Action", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.Action), ShouldEqual, layout.Members[index].Offset)
			// UINT8 Log
			index++
			So("Log", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.Log), ShouldEqual, layout.Members[index].Offset)
			// UINT8 Protocol
			index++
			So("Protocol", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.Protocol), ShouldEqual, layout.Members[index].Offset)
			// skip reserved
			index++
			// UINT8 IcmpType
			index++
			So("IcmpType", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.IcmpType), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IcmpTypeSpecified
			index++
			So("IcmpTypeSpecified", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.IcmpTypeSpecified), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IcmpCode
			index++
			So("IcmpCode", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.IcmpCode), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IcmpCodeSpecified
			index++
			So("IcmpCodeSpecified", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.IcmpCodeSpecified), ShouldEqual, layout.Members[index].Offset)
			// UINT16 ProxyPort
			index++
			So("ProxyPort", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.ProxyPort), ShouldEqual, layout.Members[index].Offset)
			// UINT16 SrcPortStart
			index++
			So("SrcPortStart", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.SrcPortStart), ShouldEqual, layout.Members[index].Offset)
			// UINT16 SrcPortEnd
			index++
			So("SrcPortEnd", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.SrcPortEnd), ShouldEqual, layout.Members[index].Offset)
			// UINT16 DstPortStart
			index++
			So("DstPortStart", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.DstPortStart), ShouldEqual, layout.Members[index].Offset)
			// UINT16 DstPortEnd
			index++
			So("DstPortEnd", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.DstPortEnd), ShouldEqual, layout.Members[index].Offset)
			// INT16 BytesMatchStart
			index++
			So("BytesMatchStart", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.BytesMatchStart), ShouldEqual, layout.Members[index].Offset)
			// INT32 BytesMatchOffset
			index++
			So("BytesMatchOffset", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.BytesMatchOffset), ShouldEqual, layout.Members[index].Offset)
			// INT32 BytesMatchSize
			index++
			So("BytesMatchSize", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.BytesMatchSize), ShouldEqual, layout.Members[index].Offset)
			// PBYTE BytesMatch
			index++
			So("BytesMatch", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.BytesMatch), ShouldEqual, layout.Members[index].Offset)
			// UINT32 Mark
			index++
			So("Mark", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.Mark), ShouldEqual, layout.Members[index].Offset)
			// UINT32 GroupId
			index++
			So("GroupId", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.GroupId), ShouldEqual, layout.Members[index].Offset)
			// LPCWCH LogPrefix
			index++
			So("LogPrefix", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.LogPrefix), ShouldEqual, layout.Members[index].Offset)
			// LPCWCH Application
			index++
			So("Application", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(RuleSpec{}.Application), ShouldEqual, layout.Members[index].Offset)
		})

		Convey("The layout of IpseRuleSpec and IPSET_RULE_SPEC should be the same", func() {
			layout, err := pdb.GetStructLayout("IPSET_RULE_SPEC")
			So(err, ShouldBeNil)
			So(unsafe.Sizeof(IpsetRuleSpec{}), ShouldEqual, layout.Size)
			// UINT8 NotIpset
			index := 0
			So("NotIpset", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(IpsetRuleSpec{}.NotIpset), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IpsetDstIp
			index++
			So("IpsetDstIp", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(IpsetRuleSpec{}.IpsetDstIp), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IpsetDstPort
			index++
			So("IpsetDstPort", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(IpsetRuleSpec{}.IpsetDstPort), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IpsetSrcIp
			index++
			So("IpsetSrcIp", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(IpsetRuleSpec{}.IpsetSrcIp), ShouldEqual, layout.Members[index].Offset)
			// UINT8 IpsetSrcPort
			index++
			So("IpsetSrcPort", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(IpsetRuleSpec{}.IpsetSrcPort), ShouldEqual, layout.Members[index].Offset)
			// skip reserved
			index++
			// LPCWCH IpsetName
			index++
			So("IpsetName", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(IpsetRuleSpec{}.IpsetName), ShouldEqual, layout.Members[index].Offset)
		})

		Convey("The layout of LogPacketInfo and FRONTMAN_LOG_PACKET_INFO should be the same", func() {
			layout, err := pdb.GetStructLayout("FRONTMAN_LOG_PACKET_INFO")
			So(err, ShouldBeNil)
			So(unsafe.Sizeof(LogPacketInfo{}), ShouldEqual, layout.Size)
			// INT32 Outbound
			index := 0
			So("Outbound", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(LogPacketInfo{}.Outbound), ShouldEqual, layout.Members[index].Offset)
			// UINT32 PacketSize
			index++
			So("PacketSize", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(LogPacketInfo{}.PacketSize), ShouldEqual, layout.Members[index].Offset)
			// UINT32 GroupId
			index++
			So("GroupId", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(LogPacketInfo{}.GroupId), ShouldEqual, layout.Members[index].Offset)
			// WCHAR LogPrefix[LOGPREFIX_MAX_LENGTH]
			index++
			So("LogPrefix", ShouldEqual, layout.Members[index].Name)
			So(unsafe.Offsetof(LogPacketInfo{}.LogPrefix), ShouldEqual, layout.Members[index].Offset)
		})

	})

}

func TestFrontmanFunctionArguments(t *testing.T) {

	const pointerSize = unsafe.Sizeof(uintptr(0))

	Convey("Given a Frontman PDB", t, func() {

		pdb, err := abi.FindFrontmanPdb()
		So(err, ShouldBeNil)

		Convey("The arguments to FrontmanGetDestInfo should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("FrontmanGetDestInfo")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 3)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to FrontmanApplyDestHandle should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("FrontmanApplyDestHandle")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 2)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to FrontmanFreeDestHandle should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("FrontmanFreeDestHandle")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 1)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to IpsetProvider_NewIpset should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("IpsetProvider_NewIpset")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 4)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
			So(funcArgs[3].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to IpsetProvider_GetIpset should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("IpsetProvider_GetIpset")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 3)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to IpsetProvider_DestroyAll should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("IpsetProvider_DestroyAll")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 2)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to IpsetProvider_ListIPSets should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("IpsetProvider_ListIPSets")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 4)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
			So(funcArgs[3].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to Ipset_Add should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("Ipset_Add")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 4)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
			So(funcArgs[3].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
		})

		Convey("The arguments to Ipset_AddOption should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("Ipset_AddOption")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 5)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
			So(funcArgs[3].Size, ShouldEqual, pointerSize)
			So(funcArgs[4].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
		})

		Convey("The arguments to Ipset_Delete should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("Ipset_Delete")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 3)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to Ipset_Destroy should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("Ipset_Destroy")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 2)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to Ipset_Flush should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("Ipset_Flush")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 2)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to Ipset_Test should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("Ipset_Test")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 3)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to PacketFilterStart should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("PacketFilterStart")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 3)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to PacketFilterClose should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("PacketFilterClose")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 0)
		})

		Convey("The arguments to PacketFilterForwardPacket should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("PacketFilterForwardPacket")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 2)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to AppendFilter should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("AppendFilter")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 3)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to InsertFilter should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("InsertFilter")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 4)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
			So(funcArgs[2].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
			So(funcArgs[3].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to DestroyFilter should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("DestroyFilter")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 2)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to EmptyFilter should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("EmptyFilter")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 2)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to GetFilterList should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("GetFilterList")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 5)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
			So(funcArgs[3].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
			So(funcArgs[4].Size, ShouldEqual, pointerSize)
		})

		Convey("The arguments to AppendFilterCriteria should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("AppendFilterCriteria")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 6)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
			So(funcArgs[3].Size, ShouldEqual, pointerSize)
			So(funcArgs[4].Size, ShouldEqual, pointerSize)
			So(funcArgs[5].Size, ShouldEqual, unsafe.Sizeof(uint32(0)))
		})

		Convey("The arguments to DeleteFilterCriteria should be as expected", func() {
			funcArgs, err := pdb.GetFunctionArguments("DeleteFilterCriteria")
			So(err, ShouldBeNil)
			So(len(funcArgs), ShouldEqual, 3)
			So(funcArgs[0].Size, ShouldEqual, pointerSize)
			So(funcArgs[1].Size, ShouldEqual, pointerSize)
			So(funcArgs[2].Size, ShouldEqual, pointerSize)
		})

	})

}
