// +build linux !windows !darwin

package conntrackwrapper

import "go.aporeto.io/netlink-go/conntrack"

type conntrackwrapper struct {
	// connctrack handle
	conntrackHdl conntrack.Conntrack
}

// New returns a handle to ConntrackWrapper
func New() ConntrackWrapper {
	return &conntrackwrapper{
		conntrackHdl: conntrack.NewHandle(),
	}
}

// ConntrackTableUpdateMark calls the netlink-go function. Indirection allows us to decouple the linux specific implementation
func (c *conntrack) ConntrackTableUpdateMark(ipSrc, ipDst string, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return c.conntrackHdl.ConntrackTableUpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark)
}
