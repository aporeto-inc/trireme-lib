package packet

import (
	"encoding/hex"
	"math/rand"
	"testing"
)

type SamplePacketName int

const (
	synBadTCPChecksum SamplePacketName = iota
	synGoodTCPChecksum
	synIHLTooBig
	synIPLenTooSmall
	synMissingBytes
	synBadIPChecksum
	loopbackAddress = "127.0.0.1"
)

var testPackets = [][]byte{
	// SYN packet captured from 'telnet localhost 99'.
	// TCP checksum is wrong.
	{0x45, 0x10, 0x00, 0x3c, 0xaa, 0x2e, 0x40, 0x00, 0x40, 0x06, 0x92,
		0x7b, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xb2, 0x64, 0x00, 0x63, 0x58, 0xd1,
		0x24, 0xd9, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x30, 0x00, 0x00, 0x02,
		0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x00, 0xc5, 0x8e, 0xf7, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03, 0x03, 0x07},

	// SYN packet captured from 'telnet localhost 99'.
	// Everything is correct.
	{0x45, 0x10, 0x00, 0x3c, 0xec, 0x6c, 0x40, 0x00, 0x40, 0x06, 0x50,
		0x3d, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x8c, 0x80, 0x00, 0x63, 0x2c, 0x32,
		0xa8, 0xd6, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x88, 0x00, 0x00, 0x02,
		0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0xff, 0xff, 0x44, 0xba, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03, 0x03, 0x07},

	// SYN packet captured from 'telnet localhost 99'.
	// IHL (IP header length) is wrong (too big, value = 6 should be 5)
	{0x46, 0x10, 0x00, 0x3c, 0xaa, 0x2e, 0x40, 0x00, 0x40, 0x06, 0x92,
		0x7b, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xb2, 0x64, 0x00, 0x63, 0x58, 0xd1,
		0x24, 0xd9, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x30, 0x00, 0x00, 0x02,
		0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x00, 0xc5, 0x8e, 0xf7, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03, 0x03, 0x07},

	// The IP packet length is incorrect (too small, value=38, should be 40)
	{0x45, 0x10, 0x00, 0x26, 0xaa, 0x2e, 0x40, 0x00, 0x40, 0x06, 0x92,
		0x7b, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xb2, 0x64, 0x00, 0x63, 0x58, 0xd1,
		0x24, 0xd9, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x30},

	// SYN packet captured from 'telnet localhost 99'.
	// Packet is too short, missing two bytes.
	{0x45, 0x10, 0x00, 0x3c, 0xaa, 0x2e, 0x40, 0x00, 0x40, 0x06, 0x92,
		0x7b, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xb2, 0x64, 0x00, 0x63, 0x58, 0xd1,
		0x24, 0xd9, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x30, 0x00, 0x00, 0x02,
		0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x00, 0xc5, 0x8e, 0xf7, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03},

	// SYN packet captured from 'telnet localhost 99'.
	// IP checksum is wrong (set to zero)
	{0x45, 0x10, 0x00, 0x3c, 0xaa, 0x2e, 0x40, 0x00, 0x40, 0x06, 0x00,
		0x00, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0xb2, 0x64, 0x00, 0x63, 0x58, 0xd1,
		0x24, 0xd9, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xaa, 0xaa, 0xfe, 0x30, 0x00, 0x00, 0x02,
		0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x00, 0xc5, 0x8e, 0xf7, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x03, 0x03, 0x07}}

func TestGoodPacket(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synGoodTCPChecksum)
	t.Log(pkt.PacketToStringTCP())

	if !pkt.VerifyIPChecksum() {
		t.Error("Test packet IP checksum failed")
	}

	if !pkt.VerifyTCPChecksum() {
		t.Error("TCP checksum failed")
	}

	if pkt.DestPort() != 99 {
		t.Error("Unexpected destination port")
	}

	if pkt.SourcePort() != 35968 {
		t.Error("Unexpected source port")
	}
}

func TestBadTCPChecknum(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synBadTCPChecksum)
	if !pkt.VerifyIPChecksum() {
		t.Error("Test packet IP checksum failed")
	}

	if pkt.VerifyTCPChecksum() {
		t.Error("Expected TCP checksum failure")
	}
}

func TestPartialChecksum(t *testing.T) {
	// Computes a checksum over the given slice.
	checksum := func(buf []byte) uint16 {
		checksumDelta := func(buf []byte) uint16 {

			sum := uint32(0)

			for ; len(buf) >= 2; buf = buf[2:] {
				sum += uint32(buf[0])<<8 | uint32(buf[1])
			}
			if len(buf) > 0 {
				sum += uint32(buf[0]) << 8
			}
			for sum > 0xffff {
				sum = (sum >> 16) + (sum & 0xffff)
			}
			return uint16(sum)
		}

		sum := checksumDelta(buf)
		csum := ^sum
		return csum
	}

	for i := 0; i < 1000; i++ {
		var randBytes [1500]byte

		rand.Read(randBytes[:])

		csum := checksum(randBytes[:])

		pCsum := partialChecksum(0, randBytes[:500])
		pCsum = partialChecksum(pCsum, randBytes[500:1000])
		pCsum = partialChecksum(pCsum, randBytes[1000:])
		fCSum := finalizeChecksum(pCsum)

		if csum != fCSum {
			t.Error("Checksum failed")
		}
	}

}

func TestAddresses(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synBadTCPChecksum)

	src := pkt.SourceAddress().String()
	if src != loopbackAddress {
		t.Errorf("Unexpected source address %s", src)
	}
	dest := pkt.DestinationAddress().String()
	if dest != loopbackAddress {
		t.Errorf("Unexpected destination address %s", src)
	}
}

func TestEmptyPacketNoPayload(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synBadTCPChecksum)

	data := pkt.ipHdr.Buffer
	if len(data) != 60 {
		t.Error("Test SYN packet should have no TCP payload")
	}
}

/*
func TestEmptyPacketNoTags(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synBadTCPChecksum)

	labels := pkt.ReadPayloadTags()
	if len(labels) != 0 {
		t.Error("Test SYN packet should have no labels")
	}

	extracted := pkt.ExtractPayloadTags()
	if len(extracted) != 0 {
		t.Error("Test SYN packet should have no extractable labels")
	}

	pkt.connection.TCPDataDetach()
	if len(pkt.Bytes) != 60 {
		t.Error("Test SYN packet should have no TCP data at all")
	}
}
*/

func TestExtractedBytesStillGood(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synBadTCPChecksum)

	// Extract unmodified bytes and feed them back in
	bytes := pkt.ipHdr.Buffer
	pkt2, err := New(0, bytes, "0", true)
	if err != nil {
		t.Fatal(err)
	}

	if !pkt2.VerifyIPChecksum() {
		t.Error("Test packet2 IP checksum failed")
	}
}

func TestLongerIPHeader(t *testing.T) {

	t.Parallel()
	err := getTestPacketWithError(synIHLTooBig)
	t.Log(err)
	if err == nil {
		t.Error("Expected failure given too long IP header length")
	}
}

func TestShortPacketLength(t *testing.T) {

	t.Parallel()
	err := getTestPacketWithError(synIPLenTooSmall)
	t.Log(err)
	if err == nil {
		t.Error("Expected failure given too short IP header length")
	}
}

func TestShortBuffer(t *testing.T) {

	t.Parallel()
	err := getTestPacketWithError(synMissingBytes)
	t.Log(err)
	if err == nil {
		t.Error("Expected failure given short (truncated) packet")
	}
}

func TestSetChecksum(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synBadIPChecksum)
	t.Log(pkt.PacketToStringTCP())
	if pkt.VerifyIPChecksum() {
		t.Error("Expected bad IP checksum given it is wrong")
	}

	pkt.UpdateIPChecksum()
	t.Log(pkt.PacketToStringTCP())
	if !pkt.VerifyIPChecksum() {
		t.Error("IP checksum is wrong after update")
	}
}

func TestSetTCPChecksum(t *testing.T) {

	t.Parallel()
	pkt := getTestPacket(t, synBadTCPChecksum)
	t.Log(pkt.PacketToStringTCP())
	if pkt.VerifyTCPChecksum() {
		t.Error("Expected bad TCP checksum given it is wrong")
	}

	pkt.UpdateTCPChecksum()
	t.Log(pkt.PacketToStringTCP())
	if !pkt.VerifyTCPChecksum() {
		t.Error("TCP checksum is wrong after update")
	}
}

func TestAddTag(t *testing.T) {

	/*
		t.Parallel()
		labels := []string{"TAG1"}
		pkt := getTestPacket(t, synBadTCPChecksum)
		if !pkt.VerifyIPChecksum() {
			t.Error("Test packet IP checksum failed")
		}

		s := pkt.String()
		t.Log(s)

		pkt.AttachPayloadTags(labels)
		if !pkt.VerifyIPChecksum() {
			t.Error("Tagged packet IP checksum failed")
		}

		s2 := pkt.String()
		t.Log(s2)

		data := string(pkt.Bytes[pkt.connection.TCPDataStartBytes():])
		t.Log("Tag extracted from payload:", data)
		if data != " "+labels[0] {
			t.Error("Tag extracted from payload data doesn't match input")
		}
	*/
}

func TestExtractTags(t *testing.T) {
	/*
		t.Parallel()
		labels := []string{"TAG1", "TAG2", "TAG3"}
		pkt := getTestPacket(t, synGoodTCPChecksum)
		t.Log("Initial packet", pkt)

		pkt.AttachPayloadTags(labels)
		t.Log("With tags", pkt)

		if !pkt.VerifyIPChecksum() {
			t.Error("Tagged packet checksum failed")
		}

		if !pkt.VerifyTCPChecksum() {
			t.Error("Packet TCP checksum failed after adding tags")
		}

		labelsRead := pkt.ExtractPayloadTags()
		t.Log("Tags extracted", pkt)

		if len(labelsRead) != 3 {
			t.Errorf("Wrote 3 labels but read %d", len(labelsRead))
		}

		for i := range labels {
			if labels[i] != labelsRead[i] {
				t.Error("Labels read do not match labels written")
			}
		}

		if !pkt.VerifyIPChecksum() {
			t.Error("Packet IP checksum failed after extracting tags")
		}

		if !pkt.VerifyTCPChecksum() {
			t.Error("Packet TCP checksum failed after extracting tags")
		}

		labelsGone := pkt.ReadPayloadTags()
		if len(labelsGone) != 0 {
			t.Error("Labels still present after extraction")
		}
	*/
}

func TestAddTags(t *testing.T) {
	/*
		t.Parallel()
		labels := []string{"TAG1", "TAG2", "TAG3"}
		pkt := getTestPacket(t, synBadTCPChecksum)
		if !pkt.VerifyIPChecksum() {
			t.Error("Test packet IP checksum failed")
		}

		t.Log(pkt.String())

		pkt.AttachPayloadTags(labels)
		if !pkt.VerifyIPChecksum() {
			t.Error("Tagged packet checksum failed")
		}

		t.Log(pkt.String())

		// Just reading tags does not remove them, so try reading twice to make sure
		for n := 0; n < 2; n++ {
			labelsRead := pkt.ReadPayloadTags()
			if len(labelsRead) != 3 {
				t.Errorf("Wrote 3 labels but read %d", len(labelsRead))
			}

			for i := range labels {
				if labels[i] != labelsRead[i] {
					t.Error("Labels read do not match labels written")
				}
			}
		}
	*/
}

func TestUDP(t *testing.T) {
	udpPacket, _ := hex.DecodeString("4500004b1a294000401108b90a8080800a0c82b400350e1700371e316e4f8180000100010000000003617069066272616e636802696f0000010001c00c000100010000003b00046354e9fa")

	pkt, _ := New(0, udpPacket, "0", true)

	if pkt.SourceAddress().String() != "10.128.128.128" {
		t.Error("source address udp parsing incorrect")
	}

	if pkt.DestinationAddress().String() != "10.12.130.180" {
		t.Error("destination address udp parsing incorrect")
	}

	if pkt.SourcePort() != uint16(53) {
		t.Error("source port incorrect udp")
	}

	if pkt.DestPort() != uint16(3607) {
		t.Error("destination port incorrect udp")
	}
}

func TestRawChecksums(t *testing.T) {

	t.Parallel()
	var buf = []byte{0x01, 0x00, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7, 0x00, 0x00}
	c := checksum(buf)
	if c != 0x210E {
		t.Error("First checksum calculation failed")
	}

	var buf2 = []byte{0x01, 0x00, 0xF2, 0x03, 0xF4, 0xF5, 0xF6, 0xF7, 0x00}
	c2 := checksum(buf2)
	if c2 != 0x210E {
		t.Error("Second checksum calculation (odd bytes) failed")
	}

	var buf3 = []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
		0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c}
	c3 := checksum(buf3)
	if c3 != 0xB1E6 {
		t.Error("Third checksum calculation failed")
	}
}

// createTCPAuthenticationOption creates the TCP authentication option -
func createTCPAuthenticationOption(token []byte) []byte {

	tokenLen := uint8(len(token))
	options := []byte{TCPAuthenticationOption, 0, 0, 0}

	if tokenLen != 0 {
		options = append(options, token...)
	}

	return options
}

func TestAuthOptions(t *testing.T) {
	pkt := getTestPacket(t, synGoodTCPChecksum)
	PacketLogLevel = true
	pkt.Print(123456)
	PacketLogLevel = false

	if err := pkt.TCPDataDetach(4); err != nil {
		t.Error("tcp data detach failed")
	}

	// We are now processing as a Trireme packet that needs authorization headers
	// Create TCP Option
	tcpOptions := createTCPAuthenticationOption([]byte{})
	pkt.tcpHdr.tcpOptions = []byte{}
	if err := pkt.TCPDataAttach(tcpOptions, []byte{}); err != nil {
		t.Error("tcp data attach failed")
	}

	pkt.ipHdr.Buffer = append(pkt.ipHdr.Buffer, pkt.GetTCPOptions()...)
	pkt.ipHdr.Buffer = append(pkt.ipHdr.Buffer, pkt.GetTCPData()...)

	if err := pkt.CheckTCPAuthenticationOption(4); err != nil {
		t.Error("tcp auth option not found")
	}

}
func TestNewPacketFunctions(t *testing.T) {
	pkt := getTestPacket(t, synGoodTCPChecksum)
	PacketLogLevel = true
	pkt.Print(123456)
	PacketLogLevel = false

	if pkt.TCPOptionLength() != 0 {
		t.Error("Test packet option length")
	}

	if pkt.TCPDataLength() != 0 {
		t.Error("Test packet IP checksum failed")
	}

	if pkt.SourcePort() != 35968 {
		t.Error("Test packet source ip didnt match")
	}

	if pkt.DestPort() != 99 {
		t.Error("Test packet dest port didnt match")
	}

	if pkt.SourceAddress().String() != loopbackAddress {
		t.Error("Test packet source ip didnt match")
	}

	if pkt.DestinationAddress().String() != loopbackAddress {
		t.Error("Test packet dest ip didnt match")
	}

	if pkt.IPProto() != IPProtocolTCP {
		t.Error("Test packet ip proto didnt match")
	}

	if pkt.IPTotalLen() != 60 {
		t.Error("Test packet total length is wrong")
	}

	if pkt.IPHeaderLen() != 20 {
		t.Error("Test packet ip header length should be 20")
	}

	if pkt.GetTCPFlags() != 2 {
		t.Error("test packet tcp flags didnt match")
	}

}

func getTestPacket(t *testing.T, id SamplePacketName) *Packet {

	tmp := make([]byte, len(testPackets[id]))
	copy(tmp, testPackets[id])

	pkt, err := New(0, tmp, "0", true)
	if err != nil {
		t.Fatal(err)
	}
	return pkt
}

func getTestPacketWithError(id SamplePacketName) error {

	tmp := make([]byte, len(testPackets[id]))
	copy(tmp, testPackets[id])

	_, err := New(0, tmp, "0", true)
	return err
}
