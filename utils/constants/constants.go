package constants

//
const (
	// MaxNFQueuesSupported is the maximum number of queues supported by this datapath.1024 -> 128 queues each for SYN/SYNACK/ACK packets default is 4
	MaxNFQueuesSupported = uint32(1 << 10)
	// NFQueueMask is used to generate a mask value on the mark to mask out NFquue index
	NFQueueMask = uint32((1 << 10) - 1)
	// MarkShift is the number of bits we shift the cgroupMark by
	MarkShift = 18

	// NFSetMarkMask is the mask to extract the mark and mask out the encoded queue
	NFSetMarkMask = ^uint32((1 << MarkShift) - 1)

	// HMARKRandomSeed is the seed to
	HMARKRandomSeed = 0x1313405

	//Initialmarkval is the start of mark values we assign to cgroup
	Initialmarkval = 100
)

const (
	// DefaultConnMark is the default conn mark for all data packets
	DefaultConnMark = uint32(0xEEEE)
	// DefaultExternalConnMark is the default conn mark for all data packets
	DefaultExternalConnMark = uint32(0xEEEF)
	// DeleteConnmark is the mark used to trigger udp handshake.
	DeleteConnmark = uint32(0xABCD)
)
