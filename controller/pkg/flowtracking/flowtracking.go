// +build linux

package flowtracking

import (
	"net"

	"github.com/aporeto-inc/conntrack"
	"github.com/mdlayher/netlink"
)

// UpdateMark updates the mark of the flow. Caller must indicate if this is an application
// flow or a network flow.
func UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, network bool) error {

	if network {
		return UpdateNetworkFlowMark(ipSrc, ipDst, protonum, srcport, dstport, newmark)
	}

	return UpdateApplicationFlowMark(ipSrc, ipDst, protonum, srcport, dstport, newmark)
}

// UpdateNetworkFlowMark will update the mark for a flow based on packet information received
// from the network. It will use the reverse tables in conntrack for that.
func UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {

	f := newReplyFlow(protonum, 0, ipSrc, ipDst, srcport, dstport, 0, newmark)

	c, err := conntrack.Dial(&netlink.Config{})
	if err != nil {
		return err
	}

	return c.Update(f)
}

// UpdateApplicationFlowMark will update the mark for a flow based on the packet information
// received from an application. It will use the forward entries of conntrack for that.
func UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {

	f := conntrack.NewFlow(protonum, 0, ipSrc, ipDst, srcport, dstport, 0, newmark)

	c, err := conntrack.Dial(&netlink.Config{})
	if err != nil {
		return err
	}

	return c.Update(f)
}

// newReplyFlow will create a flow based on the reply tuple only. This will help us
// update the mark without requiring knowledge of nats.
func newReplyFlow(proto uint8, status conntrack.StatusFlag, srcAddr, destAddr net.IP, srcPort, destPort uint16, timeout, mark uint32) conntrack.Flow {

	var f conntrack.Flow

	f.Status.Value = status

	f.Timeout = timeout
	f.Mark = mark

	// Set up TupleReply with source and destination inverted
	f.TupleReply.IP.SourceAddress = srcAddr
	f.TupleReply.IP.DestinationAddress = destAddr
	f.TupleReply.Proto.SourcePort = srcPort
	f.TupleReply.Proto.DestinationPort = destPort
	f.TupleReply.Proto.Protocol = proto

	// f.TupleOrig.IP.SourceAddress = destAddr
	// f.TupleOrig.IP.DestinationAddress = srcAddr
	// f.TupleOrig.Proto.SourcePort = destPort
	// f.TupleOrig.Proto.DestinationPort = srcPort
	// f.TupleOrig.Proto.Protocol = proto

	return f
}
