// +build windows

package flowtracking

import (
	"context"
	"fmt"
	"net"

	"go.aporeto.io/trireme-lib/controller/constants"
)

// Client is a flow update client
type Client struct {
	ignoreFlows map[string]bool
}

// NewClient creates a new flow tracking client. s
func NewClient(ctx context.Context) (*Client, error) {
	return &Client{
		ignoreFlows: make(map[string]bool),
	}, nil
}

// Close will close the connection of the client.
func (c *Client) Close() error {
	return nil
}

func (c *Client) ShouldIgnoreFlow(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16) bool {
	key := fmt.Sprintf("%d %s %d %s %d", protonum, ipSrc, srcport, ipDst, dstport)
	return c.ignoreFlows[key]
}

func (c *Client) ClearIgnoreFlow(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16) {
	key := fmt.Sprintf("%d %s %d %s %d", protonum, ipSrc, srcport, ipDst, dstport)
	delete(c.ignoreFlows, key)
}

// UpdateMark updates the mark of the flow. Caller must indicate if this is an application
// flow or a network flow.
func (c *Client) UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, network bool) error {
	if newmark == constants.DefaultConnMark {
		key := fmt.Sprintf("%d %s %d %s %d", protonum, ipSrc, srcport, ipDst, dstport)
		c.ignoreFlows[key] = true
	}
	return nil
}

// UpdateNetworkFlowMark will update the mark for a flow based on packet information received
// from the network. It will use the reverse tables in conntrack for that.
func (c *Client) UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return c.UpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark, true)
}

// UpdateApplicationFlowMark will update the mark for a flow based on the packet information
// received from an application. It will use the forward entries of conntrack for that.
func (c *Client) UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return c.UpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark, false)
}

// GetOriginalDest gets the original destination ip, port and the mark on the packet
func (c *Client) GetOriginalDest(ipSrc, ipDst net.IP, srcport, dstport uint16, protonum uint8) (net.IP, uint16, uint32, error) {
	return nil, 0, 0, nil
}
