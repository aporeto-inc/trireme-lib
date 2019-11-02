package nflog

import (
	"errors"
	"strconv"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/netlink-go/nflog"
	"go.aporeto.io/trireme-lib/v11/common"
	"go.aporeto.io/trireme-lib/v11/controller/internal/enforcer/utils/packetgen"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/v11/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/v11/policy"
)

func TestRecordDroppedPacket(t *testing.T) {
	Convey("I report a dropped packet", t, func() {
		puID := "SomeProcessingUnitId"
		puInfo := policy.NewPUInfo(puID, "/ns", common.ContainerPU)
		pu, err := pucontext.NewPU("contextID", puInfo, 5*time.Second)
		So(err, ShouldBeNil)
		nflogger := NewNFLogger(10, 11, nil, nil)
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
			report, err := nflogger.(*nfLog).recordDroppedPacket(nfPacket, pu)
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
			report, err := nflogger.(*nfLog).recordDroppedPacket(nfPacket, pu)
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
