// +build !linux

package flowtracking

import "net"

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

	return nil
}

// UpdateApplicationFlowMark will update the mark for a flow based on the packet information
// received from an application. It will use the forward entries of conntrack for that.
func UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return nil
}
