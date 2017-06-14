//PacketGen tester
//Still in beta version, Currently used for debugging
//Updates are coming soon with more test cases
package packetgen

import (
	"testing"

	"github.com/golang/mock/gomock"
)

//TestTypeInterface: to check if the type implements interface
func TestTypeInterface(t *testing.T) {
	t.Parallel()

	var PktInterface PacketManipulator = (*Packet)(nil)

	if PktInterface != (*Packet)(nil) {

		t.Error("Packet struct does not implement PacketManipulator Interface")
	}

	var PktFlowInterface PacketFlowManipulator = (*PacketFlow)(nil)
	if PktFlowInterface != (*PacketFlow)(nil) {

		t.Error("PacketFlow struct does not implement PacketFlowManipulator Interface")
	}
}

func TestForMockFlowCalls(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPacketFlows := NewMockPacketFlowManipulator(ctrl)
	firstCall := mockPacketFlows.EXPECT().GenerateTCPFlow(PacketFlowTypeGoodFlowTemplate)
	mockPacketFlows.EXPECT().GetAckPackets().After(firstCall)

	mockPacketFlows.GenerateTCPFlow(PacketFlowTypeGoodFlowTemplate)
	mockPacketFlows.GetAckPackets()
}

func TestForMockCalls(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockPacket := NewMockPacketManipulator(ctrl)

	gomock.InOrder(
		mockPacket.EXPECT().AddEthernetLayer("aa:ff:aa::aa:ff:aa", "aa:ff:ff::aa:ff:ff"),
		mockPacket.EXPECT().AddIPLayer("192.1.1.1", "10.1.1.1"),
		mockPacket.EXPECT().AddTCPLayer(gomock.Any(), gomock.Any()),
	)

	mockPacket.AddEthernetLayer("aa:ff:aa::aa:ff:aa", "aa:ff:ff::aa:ff:ff")
	mockPacket.AddIPLayer("192.1.1.1", "10.1.1.1")
	mockPacket.AddTCPLayer(666, 80)
}

//
// func TestForConnectionEstablishment(t *testing.T) {
// 	t.Parallel()
//
// 	if PacketFlows.GetFirstAckPacket().GetTCPPacket().Seq != PacketFlows.GetFirstAckPacket().GetTCPPacket().Ack {
//
// 		t.Error("Connection establishment failure")
// 	}
// }
