package packet

import "net"

const (
	// PacketTypeNetwork is enum for from-network packets
	PacketTypeNetwork = 0x1000
	// PacketTypeApplication is enum for from-application packets
	PacketTypeApplication = 0x2000

	// PacketStageIncoming is an enum for incoming stage
	PacketStageIncoming = 0x0100
	// PacketStageAuth is an enum for authentication stage
	PacketStageAuth = 0x0200
	// PacketStageService is an enum for crypto stage
	PacketStageService = 0x0400
	// PacketStageOutgoing is an enum for outgoing stage
	PacketStageOutgoing = 0x0800

	// PacketFailureCreate is the drop reason for packet
	PacketFailureCreate = 0x0010
	// PacketFailureAuth is a drop reason for packet due to authentication error
	PacketFailureAuth = 0x0020
	// PacketFailureService is a drop reason for packet due to crypto error
	PacketFailureService = 0x00040
)

func flagsToDir(flags uint64) string {

	if flags&PacketTypeApplication != 0 {
		return "<<<<<"
	} else if flags&PacketTypeNetwork != 0 {
		return ">>>>>"
	}
	return "xxxxx"
}

func flagsToStr(flags uint64) string {

	s := ""
	if flags&PacketTypeApplication != 0 {
		s = s + "Application"
	} else if flags&PacketTypeNetwork != 0 {
		s = s + "Network"
	}

	if flags&PacketStageIncoming != 0 {
		s = s + "-Incoming"
	} else if flags&PacketStageOutgoing != 0 {
		s = s + "-Outgoing"
	} else if flags&PacketStageAuth != 0 {
		s = s + "-Auth"
	} else if flags&PacketStageService != 0 {
		s = s + "-Service"
	}

	if flags&PacketFailureCreate != 0 {
		s = s + "-(Fail Create)"
	} else if flags&PacketFailureAuth != 0 {
		s = s + "-(Fail Auth)"
	} else if flags&PacketFailureService != 0 {
		s = s + "-(Fail Service)"
	}
	return s
}

func tcpFlagsToStr(flags uint8) string {
	s := ""
	if flags&0x20 == 0 {
		s = s + "."
	} else {
		s = s + "U"
	}
	if flags&0x10 == 0 {
		s = s + "."
	} else {
		s = s + "A"
	}
	if flags&0x08 == 0 {
		s = s + "."
	} else {
		s = s + "P"
	}
	if flags&0x04 == 0 {
		s = s + "."
	} else {
		s = s + "R"
	}
	if flags&0x02 == 0 {
		s = s + "."
	} else {
		s = s + "S"
	}
	if flags&0x01 == 0 {
		s = s + "."
	} else {
		s = s + "F"
	}
	return s
}

// TCPFlagsToStr converts the TCP Flags to a string value that is human readable
func TCPFlagsToStr(flags uint8) string {
	s := ""
	if flags&0x20 == 0 {
		s = s + "."
	} else {
		s = s + "U"
	}
	if flags&0x10 == 0 {
		s = s + "."
	} else {
		s = s + "A"
	}
	if flags&0x08 == 0 {
		s = s + "."
	} else {
		s = s + "P"
	}
	if flags&0x04 == 0 {
		s = s + "."
	} else {
		s = s + "R"
	}
	if flags&0x02 == 0 {
		s = s + "."
	} else {
		s = s + "S"
	}
	if flags&0x01 == 0 {
		s = s + "."
	} else {
		s = s + "F"
	}
	return s
}

// Packet is the main structure holding packet information
type Packet struct {
	// Metadata
	context uint64

	// Mark is the nfqueue Mark
	Mark string

	// Buffers : input/output buffer
	Buffer     []byte
	tcpOptions []byte
	tcpData    []byte

	// IP Header fields
	ipHeaderLen        uint8
	IPProto            uint8
	IPTotalLength      uint16
	ipID               uint16
	ipChecksum         uint16
	SourceAddress      net.IP
	DestinationAddress net.IP

	// L4 Header Fields
	SourcePort      uint16
	DestinationPort uint16
	// L4 Header Begin Position
	l4BeginPos uint16

	// TCP Specific fields
	TCPSeq        uint32
	TCPAck        uint32
	tcpDataOffset uint8
	TCPFlags      uint8
	TCPChecksum   uint16

	// Service Metadata
	SvcMetadata interface{}
	// Connection Metadata
	ConnectionMetadata interface{}
}
