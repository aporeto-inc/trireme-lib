//Packet generator test for TCP and IP
//Change values of TCP header fields
//Still in beta version
//Updates are coming soon for more options to IP, hopefully ethernet too
//Test cases are created only for generated packets, not for packets on the wire
package packetgen

import "testing"

func TestTypeInterface(t *testing.T) {
	t.Parallel()

	var PktInterface PacketManipulator = (*Packet)(nil)

	if PktInterface != (*Packet)(nil) {

		t.Error("Packet struct does not implement Pkt Interface")

	}

	var PktFlowInterface PacketFlowManipulator = (*PacketFlow)(nil)
	if PktFlowInterface != (*PacketFlow)(nil) {

		t.Error("PacketFlow struct does not implement PktFlow Interface")

	}

}
