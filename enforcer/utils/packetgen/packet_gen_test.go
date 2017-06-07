//Packet generator test for TCP and IP
//Change values of TCP header fields
//Still in beta version
//Updates are coming soon for more options to IP, hopefully ethernet too
//Test cases are created only for generated packets, not for packets on the wire
package packetgen

import (
	"fmt"
	"testing"
)

//. "github.com/smartystreets/goconvey/convey"

var (
	TCPFlow        [][]byte
	InvalidTCPFlow [][]byte
	layer          PacketFlow
	TCPPacket	Packet
)

func init() {
fmt.Println()
	//fmt.Println(NewPacket().AddIPLayer("122.1.1.1.", "122.2.3.4"))
	p:=NewPacket()
	p.AddIPLayer("164.67.228.152", "10.1.10.76")
	p.AddTCPLayer(666,80)
	p.ToBytes()
	pf:=NewPacketFlow(p)
	fmt.Println(pf)
	//p.ChangeTCPSequenceNumber(2345)
	//p.DisplayTCPPacket()
	// layer.SrcIPstr = "164.67.228.152"
	// layer.DstIPstr = "10.1.10.76"
	// ipLayer := layer.GenerateIPPacket(layer.SrcIPstr, layer.DstIPstr)
	// layer.SrcPort = 666
	// layer.DstPort = 80
	// layer.GenerateTCPPacket(&ipLayer, layer.SrcPort, layer.DstPort)
	// layer.SetSynTrue()
	// layer.SequenceNum = 0
	// //layer.InitTemplate()
	// TCPFlow = layer.GenerateTCPFlow(layer.TemplateFlow)
	// //TCPFlow = layer.GenerateTCPFlowPayload("Aporeto Confidential")

}
//
func TestSample(t *testing.T) {}
//
// //check th enumber of tcp layers generated
// func TestCount(t *testing.T) {
//
// 	t.Parallel()
//
// 	if len(TCPFlow) != 3 {
// 		t.Error("Cannot generate TCP flow, missing either SYN, SYNACK or ACK packets")
// 	}
//
// }
//
// //check for payload in packets
// func TestForPayloadAvailability(t *testing.T) {
//
// 	t.Parallel()
//
// }
//
// //check if Syn is set for the first packet
// func TestForSYNPacket(t *testing.T) {
//
// 	t.Parallel()
//
// 	if layer.Layers[0].SYN != true && layer.Layers[0].ACK == true {
// 		t.Error("No SYN packet in starting flow")
// 	}
//
// }
//
// //check if ethernet is removed from the layers to support datapath_test
// func TestEthernetPresence(t *testing.T) {
//
// 	t.Parallel()
//
// 	for i, _ := range TCPFlow {
// 		if len(TCPFlow[i]) != 46 {
// 			t.Errorf("Ethernet not supported. Check this layer %d", TCPFlow[i])
// 		}
// 	}
//
// }
//
// //check if the TCP flow is good
// func TestGoodPacketFlow(t *testing.T) {
//
// 	t.Parallel()
//
// 	if layer.Layers[0].SrcPort != layer.SrcPort {
// 		t.Error("unexpected source port")
// 	}
//
// 	if layer.Layers[0].DstPort != layer.DstPort {
// 		t.Error("unexpected destination port")
// 	}
//
// 	if layer.Layers[1].SrcPort != layer.DstPort {
// 		t.Error("wrong SynAck port set")
// 	}
//
// 	if layer.Layers[1].DstPort != layer.SrcPort {
// 		t.Error("wrong SynAck port set")
// 	}
//
// }

// func TestTypeInterface(t *testing.T) {
// 	t.Parallel()
//
// 	var PktInterface Pkt = (*Packet)(nil)
//
// 	if PktInterface != (*Packet)(nil) {
//
// 		t.Error("Packet struct does not implement Pkt Interface")
//
// 	}
//
// 	var PktFlowInterface PktFlow = (*PacketFlow)(nil)
// 	if PktFlowInterface != (*PacketFlow)(nil) {
//
// 		t.Error("PacketFlow struct does not implement PktFlow Interface")
//
// 	}
//
// }
