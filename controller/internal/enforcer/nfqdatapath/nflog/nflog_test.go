package nflog

import (
	"strconv"
	"testing"
	"time"

	. "github.com/smartystreets/goconvey/convey"
	"go.aporeto.io/netlink-go/nflog"
	"go.aporeto.io/trireme-lib/common"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/utils/packetgen"
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
		nflogger := NewNFLogger(10, 11, nil, nil)
		Convey("I report a packet with length less than 64 bytes", func() {
			//	packetbuf := make([]byte, 40)
			PacketFlow := packetgen.NewTemplateFlow()

			_, err := PacketFlow.GenerateTCPFlow(packetgen.PacketFlowTypeGoodFlowTemplate)
			So(err, ShouldBeNil)
			packet := PacketFlow.GetNthPacket(0)
			payloadBuf, _ := packet.ToBytes()
			nfPacket := &nflog.NfPacket{
				Payload: payloadBuf,
			}
			report := nflogger.(*nfLog).recordDroppedPacket(nfPacket, pu)
			So(report.TriremePacket, ShouldBeFalse)
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

			So(err, ShouldBeNil)
			report := nflogger.(*nfLog).recordDroppedPacket(nfPacket, pu)
			So(report.TriremePacket, ShouldBeFalse)
			So(len(report.Payload), ShouldEqual, 64)
			id, _ := strconv.Atoi(ipPacket.ID())
			So(report.PacketID, ShouldEqual, id)

			So(report.Payload, ShouldResemble, payloadBuf[:64])
		})

	})
}
