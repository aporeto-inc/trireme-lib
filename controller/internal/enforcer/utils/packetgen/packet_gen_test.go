//+build !test

//PacketGen tester
//Still in beta version, Currently used for debugging
//Updates are coming soon with more test cases
package packetgen

import "testing"

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
