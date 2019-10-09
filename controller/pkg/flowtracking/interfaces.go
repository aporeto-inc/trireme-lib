package flowtracking

import "net"

// FlowClient defines an interface that trireme uses to communicate with the conntrack
type FlowClient interface {
	// Close will close the connection of the client.
	Close() error
	// UpdateMark updates the mark of the flow. Caller must indicate if this is an application
	// flow or a network flow.
	UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, data interface{}, network bool) error
	// GetOriginalDest gets the original destination ip, port and the mark on the packet
	GetOriginalDest(ipSrc, ipDst net.IP, srcport, dstport uint16, protonum uint8) (net.IP, uint16, uint32, error)
	// UpdateNetworkFlowMark will update the mark for a flow based on packet information received
	// from the network. It will use the reverse tables in conntrack for that.
	UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, data interface{}) error
	// UpdateApplicationFlowMark will update the mark for a flow based on the packet information
	// received from an application. It will use the forward entries of conntrack for that.
	UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, data interface{}) error
}
