// +build windows

package nfqdatapath

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"unsafe"

	"github.com/golang/mock/gomock"
	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/constants"
	"go.aporeto.io/enforcerd/trireme-lib/controller/internal/enforcer/utils/packetgen"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/frontman"
)

// Declare function pointer so that it can be overridden by unit test.
// This is not actually needed in Windows, but we need the declaration and the empty function for tests.
var procSetValuePtr func(procName string, value int) error = procSetValueMock

type forwardedPacket struct {
	outbound, drop, ignoreFlow bool
	mark                       int
	packetBytes                []byte
}

// fakeWrapper is the mock for frontman.Wrapper.
// We mock frontman.Wrapper and not frontman.Driver because we need to save the go funcs passed to PacketFilterStart.
type fakeWrapper struct {
	receiveCallback, loggingCallback func(uintptr, uintptr) uintptr
	forwardedPackets                 []*forwardedPacket
	sync.Mutex
}

func (w *fakeWrapper) queuePacket(p *forwardedPacket) {
	w.Lock()
	defer w.Unlock()
	w.forwardedPackets = append(w.forwardedPackets, p)
}

func (w *fakeWrapper) GetForwardedPackets() []*forwardedPacket {
	w.Lock()
	defer w.Unlock()
	result := w.forwardedPackets
	w.forwardedPackets = nil
	return result
}

func (w *fakeWrapper) PacketFilterStart(firewallName string, receiveCallback, loggingCallback func(uintptr, uintptr) uintptr) error {
	w.receiveCallback = receiveCallback
	w.loggingCallback = loggingCallback
	return nil
}

func (w *fakeWrapper) PacketFilterForward(info *frontman.PacketInfo, packetBytes []byte) error {
	p := &forwardedPacket{
		outbound:    info.Outbound != 0,
		drop:        info.Drop != 0,
		ignoreFlow:  info.IgnoreFlow != 0,
		mark:        int(info.Mark),
		packetBytes: make([]byte, info.PacketSize),
	}
	if n := copy(p.packetBytes, packetBytes); n != int(info.PacketSize) {
		return fmt.Errorf("%d bytes copied for packet, but expected %d", n, info.PacketSize)
	}
	w.queuePacket(p)
	return nil
}

func Test_WindowsPacketCallbacks(t *testing.T) {

	// unused in Windows
	_ = testDstIP
	_ = debug

	Convey("Given I create a new enforcer instance for Windows and have a valid processing unit context", t, func() {

		wrapper := &fakeWrapper{}
		frontman.Wrapper = wrapper

		Convey("Given I create a two processing unit instances", func() {

			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			enforcer, mockCollector := createEnforcerWithPolicy(ctrl, constants.LocalServer)

			err := enforcer.startFrontmanPacketFilter(context.Background(), enforcer.nflogger)
			So(err, ShouldBeNil)

			Convey("When I pass a syn packet through the enforcer", func() {

				PacketFlow := packetgen.NewTemplateFlow()
				_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
				So(err, ShouldBeNil)
				tcpPacketFromFlow, err := PacketFlow.GetFirstSynPacket().ToBytes()
				So(err, ShouldBeNil)
				mark := 12345
				tcpPacket, err := packet.New(0, tcpPacketFromFlow, strconv.Itoa(mark), true)
				if err == nil && tcpPacket != nil {
					tcpPacket.UpdateIPv4Checksum()
					tcpPacket.UpdateTCPChecksum()
				}
				So(err, ShouldBeNil)
				So(tcpPacket.Mark, ShouldEqual, strconv.Itoa(mark))

				packetBytes := tcpPacket.GetTCPBytes()
				packetInfo := &frontman.PacketInfo{
					Ipv4:       1,
					Protocol:   tcpPacket.IPProto(),
					PacketSize: uint32(len(packetBytes)),
					Mark:       uint32(mark),
				}
				if tcpPacket.SourceAddress().String() == testSrcIP {
					packetInfo.Outbound = 1
				}
				ret := wrapper.receiveCallback(uintptr(unsafe.Pointer(packetInfo)), uintptr(unsafe.Pointer(&packetBytes[0])))
				So(ret, ShouldBeZeroValue)

				oldPacket := tcpPacket
				forwardedPackets := wrapper.GetForwardedPackets()
				So(forwardedPackets, ShouldHaveLength, 1)
				tcpPacket, err = packet.New(0, forwardedPackets[0].packetBytes, strconv.Itoa(mark), true)
				So(err, ShouldBeNil)

				// In our 3 way security handshake syn and syn-ack packet should grow in length
				So(tcpPacket.GetTCPFlags()&packet.TCPSynMask, ShouldNotBeZeroValue)
				So(tcpPacket.IPTotalLen(), ShouldBeGreaterThan, oldPacket.IPTotalLen())

				// reverse it and strip identity
				packetInfo.Outbound ^= 1
				packetBytes = tcpPacket.GetTCPBytes()
				packetInfo.PacketSize = uint32(len(packetBytes))
				ret = wrapper.receiveCallback(uintptr(unsafe.Pointer(packetInfo)), uintptr(unsafe.Pointer(&packetBytes[0])))
				So(ret, ShouldBeZeroValue)
				forwardedPackets = wrapper.GetForwardedPackets()
				So(forwardedPackets, ShouldHaveLength, 1)
				tcpPacket, err = packet.New(0, forwardedPackets[0].packetBytes, strconv.Itoa(mark), true)
				So(err, ShouldBeNil)
				So(tcpPacket.IPTotalLen(), ShouldEqual, oldPacket.IPTotalLen())
			})

			Convey("When I pass a synack packet for non-PU traffic", func() {

				PacketFlow := packetgen.NewTemplateFlow()
				_, err = PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
				So(err, ShouldBeNil)
				tcpPacketFromFlow, err := PacketFlow.GetFirstSynAckPacket().ToBytes()
				So(err, ShouldBeNil)
				mark := 12345
				tcpPacket, err := packet.New(0, tcpPacketFromFlow, strconv.Itoa(mark), true)
				if err == nil && tcpPacket != nil {
					tcpPacket.UpdateIPv4Checksum()
					tcpPacket.UpdateTCPChecksum()
				}
				So(err, ShouldBeNil)
				So(tcpPacket.Mark, ShouldEqual, strconv.Itoa(mark))

				packetBytes := tcpPacket.GetTCPBytes()
				packetInfo := &frontman.PacketInfo{
					Ipv4:       1,
					Protocol:   tcpPacket.IPProto(),
					PacketSize: uint32(len(packetBytes)),
					Mark:       uint32(mark),
				}
				if tcpPacket.SourceAddress().String() == testSrcIP {
					packetInfo.Outbound = 1
				}
				ret := wrapper.receiveCallback(uintptr(unsafe.Pointer(packetInfo)), uintptr(unsafe.Pointer(&packetBytes[0])))
				So(ret, ShouldBeZeroValue)

				forwardedPackets := wrapper.GetForwardedPackets()
				So(forwardedPackets, ShouldHaveLength, 1)
				tcpPacket, err = packet.New(0, forwardedPackets[0].packetBytes, strconv.Itoa(mark), true)
				So(err, ShouldBeNil)
				So(tcpPacket, ShouldNotBeNil)
				// IgnoreFlow flag should be set
				So(forwardedPackets[0].ignoreFlow, ShouldNotBeZeroValue)
			})

			Convey("When I say to log that a packet is rejected", func() {

				puHash, err := policy.Fnv32Hash("SomeProcessingUnitId1")
				So(err, ShouldBeNil)

				dnsRequestPacket, err := hex.DecodeString("450000380542000080110000c0a8446dc0a84401ebe60035002409f5df510100000100000000000006676f6f676c6503636f6d0000010001")
				So(err, ShouldBeNil)
				dnsPacket, err := packet.New(0, dnsRequestPacket, "0", true)
				So(err, ShouldBeNil)

				packetHeaderBytes := dnsPacket.GetBuffer(0)[:dnsPacket.IPHeaderLen()+packet.UDPDataPos]
				logPacketInfo := &frontman.LogPacketInfo{
					Ipv4:       1,
					Protocol:   dnsPacket.IPProto(),
					PacketSize: uint32(len(packetHeaderBytes)),
					GroupID:    11,
				}

				copy(logPacketInfo.LogPrefix[:], syscall.StringToUTF16(puHash+":5d6044b9e99572000149d650:5d60448a884e46000145cf67:6")) // nolint:staticcheck

				flowRecord := CreateFlowRecord(1, "192.168.68.109", "192.168.68.1", 0, 53, policy.Reject|policy.Log, collector.PolicyDrop)
				mockCollector.EXPECT().CollectFlowEvent(MyMatcher(&flowRecord)).Times(1)

				ret := wrapper.loggingCallback(uintptr(unsafe.Pointer(logPacketInfo)), uintptr(unsafe.Pointer(&packetHeaderBytes[0])))
				So(ret, ShouldBeZeroValue)
			})
		})
	})
}

// Empty interface implementations

func (w *fakeWrapper) GetDestInfo(socket uintptr, destInfo *frontman.DestInfo) error {
	return nil
}

func (w *fakeWrapper) ApplyDestHandle(socket, destHandle uintptr) error {
	return nil
}

func (w *fakeWrapper) FreeDestHandle(destHandle uintptr) error {
	return nil
}

func (w *fakeWrapper) NewIpset(name, ipsetType string) (uintptr, error) {
	return 1, nil
}

func (w *fakeWrapper) GetIpset(name string) (uintptr, error) {
	return 1, nil
}

func (w *fakeWrapper) DestroyAllIpsets(prefix string) error {
	return nil
}

func (w *fakeWrapper) ListIpsets() ([]string, error) {
	return nil, nil
}

func (w *fakeWrapper) ListIpsetsDetail(format int) (string, error) {
	return "", nil
}

func (w *fakeWrapper) IpsetAdd(ipsetHandle uintptr, entry string, timeout int) error {
	return nil
}

func (w *fakeWrapper) IpsetAddOption(ipsetHandle uintptr, entry, option string, timeout int) error {
	return nil
}

func (w *fakeWrapper) IpsetDelete(ipsetHandle uintptr, entry string) error {
	return nil
}

func (w *fakeWrapper) IpsetDestroy(ipsetHandle uintptr, name string) error {
	return nil
}

func (w *fakeWrapper) IpsetFlush(ipsetHandle uintptr) error {
	return nil
}

func (w *fakeWrapper) IpsetTest(ipsetHandle uintptr, entry string) (bool, error) {
	return true, nil
}

func (w *fakeWrapper) AppendFilter(outbound bool, filterName string, isGotoFilter bool) error {
	return nil
}

func (w *fakeWrapper) InsertFilter(outbound bool, priority int, filterName string, isGotoFilter bool) error {
	return nil
}

func (w *fakeWrapper) DestroyFilter(filterName string) error {
	return nil
}

func (w *fakeWrapper) EmptyFilter(filterName string) error {
	return nil
}

func (w *fakeWrapper) GetFilterList(outbound bool) ([]string, error) {
	return nil, nil
}

func (w *fakeWrapper) AppendFilterCriteria(filterName, criteriaName string, ruleSpec *frontman.RuleSpec, ipsetRuleSpecs []frontman.IpsetRuleSpec) error {
	return nil
}

func (w *fakeWrapper) DeleteFilterCriteria(filterName, criteriaName string) error {
	return nil
}

func (w *fakeWrapper) GetCriteriaList(format int) (string, error) {
	return "", nil
}

func (w *fakeWrapper) PacketFilterClose() error {
	return nil
}
