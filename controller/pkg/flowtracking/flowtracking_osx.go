// +build !linux

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
