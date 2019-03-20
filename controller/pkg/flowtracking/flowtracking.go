// +build linux

package flowtracking

import (
	"context"
	"fmt"
	"net"

	"github.com/aporeto-inc/conntrack"
	"github.com/mdlayher/netlink"
)

// Client is a flow update client
type Client struct {
	conn *conntrack.Conn
}

// NewClient creates a new flow tracking client. s
func NewClient(ctx context.Context) (*Client, error) {
	c, err := conntrack.Dial(&netlink.Config{})
	if err != nil {
		return nil, fmt.Errorf("flow tracker is unable to dial netlink: %s", err)
	}

	client := &Client{conn: c}
	go func() {
		<-ctx.Done()
		client.conn.Close() // nolint errcheck
	}()

	return client, nil
}

// Close will close the connection of the client.
func (c *Client) Close() error {
	return c.conn.Close()
}

// UpdateMark updates the mark of the flow. Caller must indicate if this is an application
// flow or a network flow.
func (c *Client) UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, network bool) error {

	if network {
		return c.UpdateNetworkFlowMark(ipSrc, ipDst, protonum, srcport, dstport, newmark)
	}

	return c.UpdateApplicationFlowMark(ipSrc, ipDst, protonum, srcport, dstport, newmark)
}

// UpdateNetworkFlowMark will update the mark for a flow based on packet information received
// from the network. It will use the reverse tables in conntrack for that.
func (c *Client) UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {

	f := newReplyFlow(protonum, 0, ipSrc, ipDst, srcport, dstport, 0, newmark)

	return c.conn.Update(f)
}

// UpdateApplicationFlowMark will update the mark for a flow based on the packet information
// received from an application. It will use the forward entries of conntrack for that.
func (c *Client) UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {

	f := conntrack.NewFlow(protonum, 0, ipSrc, ipDst, srcport, dstport, 0, newmark)

	return c.conn.Update(f)
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

	return f
}
