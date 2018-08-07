package conntrackwrapper

type ConntrackWrapper interface {
	ConntrackTableUpdateMark(ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) error
}
