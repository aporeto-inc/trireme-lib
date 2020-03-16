// +build !windows

package nflog

import (
	"errors"
	"strconv"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/netlink-go/nflog"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/packetgen"
	"go.aporeto.io/trireme-lib/controller/pkg/counters"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/policy"
)

func TestRecordDroppedPacket(t *testing.T) {
	Convey("I report a dropped packet", t, func() {
		puID := "SomeProcessingUnitId"
		puInfo := policy.NewPUInfo(puID, "/ns", common.ContainerPU)
		pu, err := pucontext.NewPU("contextID", puInfo, 5*time.Second)
		So(err, ShouldBeNil)

		Convey("I report a packet with length less than 64 bytes", func() {
			//	packetbuf := make([]byte, 40)
			PacketFlow := packetgen.NewTemplateFlow()

			_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)
			pkt := PacketFlow.GetNthPacket(0)
			payloadBuf, _ := pkt.ToBytes()
			nfPacket := &nflog.NfPacket{
				Payload: payloadBuf,
			}
			ipPacket, err := packet.New(packet.PacketTypeNetwork, nfPacket.Payload, "", false)
			So(err, ShouldBeNil)
			nfPacket.Protocol = ipPacket.IPProto()
			report, err := recordDroppedPacket(nfPacket.Payload, nfPacket.Protocol, nfPacket.SrcIP, nfPacket.DstIP, nfPacket.SrcPort, nfPacket.DstPort, pu, true)
			So(report.TriremePacket, ShouldBeFalse)
			So(err, ShouldBeNil)
			So(len(report.Payload), ShouldEqual, len(nfPacket.Payload))

		})
		Convey("I report a packet with length greater than 64 bytes", func() {
			PacketFlow := packetgen.NewTemplateFlow()
			_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)
			pkt := PacketFlow.GetAckPackets().GetNthPacket(1)
			err = pkt.NewTCPPayload("abcdedghijklmnopqrstuvwxyz")
			So(err, ShouldBeNil)
			payloadBuf, err := pkt.ToBytes()
			So(err, ShouldBeNil)
			nfPacket := &nflog.NfPacket{
				Payload: payloadBuf,
			}

			ipPacket, err := packet.New(packet.PacketTypeNetwork, nfPacket.Payload, "", false)
			nfPacket.Protocol = ipPacket.IPProto()
			nfPacket.SrcIP = ipPacket.SourceAddress()
			nfPacket.DstIP = ipPacket.DestinationAddress()
			So(err, ShouldBeNil)
			report, err := recordDroppedPacket(nfPacket.Payload, nfPacket.Protocol, nfPacket.SrcIP, nfPacket.DstIP, nfPacket.SrcPort, nfPacket.DstPort, pu, true)
			So(err, ShouldBeNil)
			So(report.TriremePacket, ShouldBeFalse)
			So(report.Protocol, ShouldEqual, int(packet.IPProtocolTCP))
			So(len(report.Payload), ShouldEqual, 64)
			id, _ := strconv.Atoi(ipPacket.ID())
			So(report.PacketID, ShouldEqual, id)
			So(report.SourceIP, ShouldEqual, ipPacket.SourceAddress().String())
			So(report.DestinationIP, ShouldEqual, ipPacket.DestinationAddress().String())

			So(report.Payload, ShouldResemble, payloadBuf[:64])
		})

	})
}

func dummyPUContext(string) (*pucontext.PUContext, error) {
	return nil, errors.New("Unknown Context")
}
func TestRecordFromNFLogBuffer(t *testing.T) {
	// puID := "SomeProcessingUnitId"
	// puInfo := policy.NewPUInfo(puID, "/ns", common.ContainerPU)
	// pu, err := pucontext.NewPU("contextID", puInfo, 5*time.Second)
	// So(err, ShouldBeNil)
	nflogger := NewNFLogger(10, 11, nil, nil)
	Convey("I get a nfpacket from nflog library", t, func() {
		Convey("If Packet does not contain valid format prefix", func() {
			PacketFlow := packetgen.NewTemplateFlow()

			_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)
			pkt := PacketFlow.GetNthPacket(0)
			payloadBuf, _ := pkt.ToBytes()
			nfPacket := &nflog.NfPacket{
				Payload: payloadBuf,
			}
			nfPacket.Prefix = "p1:p2"
			flowreport, packetreport, err := nflogger.(*nfLog).recordFromNFLogBuffer(nfPacket, false)
			So(flowreport, ShouldBeNil)
			So(packetreport, ShouldBeNil)
			So(err, ShouldNotBeNil)
		})
		Convey("nfPacket with hashID that is not for a valid PU", func() {

			nflogger.(*nfLog).getPUContext = dummyPUContext
			PacketFlow := packetgen.NewTemplateFlow()

			_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)
			pkt := PacketFlow.GetNthPacket(0)
			payloadBuf, _ := pkt.ToBytes()
			nfPacket := &nflog.NfPacket{
				Payload: payloadBuf,
			}
			nfPacket.Prefix = "p1:p2:p4:p5"
			flowreport, packetreport, err := nflogger.(*nfLog).recordFromNFLogBuffer(nfPacket, false)
			So(flowreport, ShouldBeNil)
			So(packetreport, ShouldBeNil)
			So(err, ShouldNotBeNil)

		})

	})
}

func Test_RecordCounters(t *testing.T) {
	Convey("I report a dropped packet", t, func() {
		puID := "SomeProcessingUnitId"
		puInfo := policy.NewPUInfo(puID, "/ns", common.ContainerPU)
		pu, err := pucontext.NewPU("contextID", puInfo, 5*time.Second)
		So(err, ShouldBeNil)

		Convey("I call record counters", func() {
			recordCounters(6, 80, 2333, pu, true)
			So(pu.Counters().GetErrorCounters()[counters.ErrDroppedTCPPackets], ShouldEqual, 1)

			recordCounters(17, 80, 2333, pu, true)
			c := pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			recordCounters(17, 53, 2333, pu, true)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			So(c[counters.ErrDroppedDNSPackets], ShouldEqual, 1)
			recordCounters(17, 67, 2333, pu, true)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			So(c[counters.ErrDroppedDHCPPackets], ShouldEqual, 1)
			recordCounters(17, 68, 2333, pu, true)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			So(c[counters.ErrDroppedDHCPPackets], ShouldEqual, 1)
			recordCounters(17, 123, 2333, pu, true)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			So(c[counters.ErrDroppedNTPPackets], ShouldEqual, 1)

			recordCounters(17, 2333, 53, pu, false)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			So(c[counters.ErrDroppedDNSPackets], ShouldEqual, 1)
			recordCounters(17, 2333, 67, pu, false)
			recordCounters(17, 2333, 67, pu, false)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 2)
			So(c[counters.ErrDroppedDHCPPackets], ShouldEqual, 2)
			recordCounters(17, 2333, 68, pu, false)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			So(c[counters.ErrDroppedDHCPPackets], ShouldEqual, 1)
			recordCounters(17, 2333, 123, pu, false)
			c = pu.Counters().GetErrorCounters()
			So(c[counters.ErrDroppedUDPPackets], ShouldEqual, 1)
			So(c[counters.ErrDroppedNTPPackets], ShouldEqual, 1)

			recordCounters(1, 80, 2333, pu, true)
			So(pu.Counters().GetErrorCounters()[counters.ErrDroppedICMPPackets], ShouldEqual, 1)
		})
	})
}
