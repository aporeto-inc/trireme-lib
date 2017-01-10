package packet

const (
	// minIPPacketLen is the min ip packet size
	minIPPacketLen = 40

	// minIPHdrSize
	minIPHdrSize = 20

	minIPHdrWords = (minIPHdrSize / 4)
)

// IP Header field position constants
const (
	// ipHdrLenPos is location of IP (entire packet) length
	ipHdrLenPos = 0

	// ipLengthPos is location of IP (entire packet) length
	ipLengthPos = 2

	// ipIDPos is location of IP Identifier
	IPIDPos = 4

	// ipProtoPos is the location of the IP Protocol
	ipProtoPos = 9

	// ipChecksumPos is location of IP checksum
	ipChecksumPos = 10

	// ipSourceAddrPos is location of source IP address
	ipSourceAddrPos = 12

	// ipDestAddrPos is location of destination IP address
	ipDestAddrPos = 16
)

// IP Protocol numbers
const (
	// IPProtocolTCP defines the constant for UDP protocol number
	IPProtocolTCP = 6

	// IPProtocolUDP defines the constant for UDP protocol number
	IPProtocolUDP = 17
)

// IP Header masks
const (
	ipHdrLenMask = 0xF
)

// TCP Header field position constants
const (
	// tcpSourcePortPos is the location of source port
	tcpSourcePortPos = 20

	// tcpDestPortPos is the location of destination port
	tcpDestPortPos = 22

	// tcpSeqPos is the location of seq
	tcpSeqPos = 24

	// tcpAckPos is the location of seq
	tcpAckPos = 28

	// tcpDataOffsetPos is the location of the TCP data offset
	tcpDataOffsetPos = 32

	//tcpFlagsOfsetPos is the location of the TCP flags
	tcpFlagsOffsetPos = 33

	// TCPChecksumPos is the location of TCP checksum
	TCPChecksumPos = 36
)

// TCP Header masks
const (
	// tcpDataOffsetMask is a mask for TCP data offset field
	tcpDataOffsetMask = 0xF0

	// TCPSynMask is a mask for the TCP Syn flags
	TCPSynMask = 0x2

	// TCPSynAckMask  mask idenitifies a TCP SYN-ACK packet
	TCPSynAckMask = 0x12

	// TCPRstMask mask that identifies RST packets
	TCPRstMask = 0x4

	// TCPAckMask mask that identifies ACK packets
	TCPAckMask = 0x10

	// TCPFinMask mask that identifies FIN packets
	TCPFinMask = 0x1
)

// TCP Options Related constants
const (
	// TCPAuthenticationOption is the option number will be using
	TCPAuthenticationOption = uint8(255)

	// TCPMssOption is the type for MSS option
	TCPMssOption = uint8(2)

	// TCPMssOptionLen is the type for MSS option
	TCPMssOptionLen = uint8(4)
)
