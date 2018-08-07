// +build linux

package conntrackwrapper

import "go.aporeto.io/netlink-go/conntrack"

type conntrackwrapper struct {
	// connctrack handle
	conntrackHdl conntrack.Conntrack
}

func New() ConntrackWrapper {
	return &conntrack{
		conntrackHdl: conntrack.NewHandle(),
	}
}

func (c *conntrack) ConntrackTableUpdateMark(ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return c.conntrackHdl.ConntrackTableUpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark)
}
