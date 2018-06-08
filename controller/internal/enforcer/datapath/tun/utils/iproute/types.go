package iproute

// nolint
// Definitions from linux header files
const (
	// RTA_OIF  Routing Attribute outgoing interface
	RTA_OIF = 0x4 // nolint
	// RTA_GATEWAY Routing attribute gateway ip
	RTA_GATEWAY = 0x5
	// RTA_PRIORITY  priority of the ip rule
	RTA_PRIORITY = 0x6
	// RTA_MARK routing attribute mark
	RTA_MARK = 10
	// RTA_MARK_MASK routing attribute mask bits for the markval
	RTA_MARK_MASK = 16
)
