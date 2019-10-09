// +build windows

package flowtracking

import (
	"context"
	"errors"
	"net"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
)

// Client is a flow update client.
// For Windows, we can't use conntrack.
type Client struct {
}

// NewClient creates a new flow tracking client.
func NewClient(ctx context.Context) (*Client, error) {
	return &Client{}, nil
}

// Close will close the connection of the client.
func (c *Client) Close() error {
	return nil
}

// UpdateMark adds an entry to the map.
func (c *Client) UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, data interface{}, network bool) error {
	if newmark == constants.DefaultConnMark {
		windata, _ := data.(*afinetrawsocket.WindowsPacketMetadata)
		if windata == nil {
			return errors.New("no WindowsPacketMetadata for UpdateMark")
		}
		windata.IgnoreFlow = true
	}
	return nil
}

func (c *Client) UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, data interface{}) error {
	return c.UpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark, data, true)
}

func (c *Client) UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, data interface{}) error {
	return c.UpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark, data, false)
}

func (c *Client) GetOriginalDest(ipSrc, ipDst net.IP, srcport, dstport uint16, protonum uint8) (net.IP, uint16, uint32, error) {
	return nil, 0, 0, nil
}
