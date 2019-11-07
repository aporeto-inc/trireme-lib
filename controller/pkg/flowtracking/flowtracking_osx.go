// +build darwin

package flowtracking

import (
	"context"
	"net"
)

// Client is a flow update client
type Client struct {
}

// NewClient creates a new flow tracking client. s
func NewClient(ctx context.Context) (*Client, error) {
	return nil, nil
}

// Close will close the connection of the client.
func (c *Client) Close() error {
	return nil
}

// UpdateMark updates the mark of the flow. Caller must indicate if this is an application
// flow or a network flow.
func (c *Client) UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, network bool) error {
	return nil
}

// UpdateNetworkFlowMark will update the mark for a flow based on packet information received
// from the network. It will use the reverse tables in conntrack for that.
func (c *Client) UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return nil
}

// UpdateApplicationFlowMark will update the mark for a flow based on the packet information
// received from an application. It will use the forward entries of conntrack for that.
func (c *Client) UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return nil
}

// GetOriginalDest gets the original destination ip, port and the mark on the packet
func (c *Client) GetOriginalDest(ipSrc, ipDst net.IP, srcport, dstport uint16, protonum uint8) (net.IP, uint16, uint32, error) {
	return nil, 0, 0, nil
}

// NotifyIgnoreFlow is for Windows, because we need a way to explicitly notify of an 'ignore flow' condition, to be called synchronously in datapath processing
func (c *Client) NotifyIgnoreFlow(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, data interface{}) error {
	return nil
}
