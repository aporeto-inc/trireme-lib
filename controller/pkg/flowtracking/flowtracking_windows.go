// +build windows

package flowtracking

import (
	"context"
	"fmt"
	"net"
	"sync"

	"go.aporeto.io/trireme-lib/controller/constants"
)

// Client is a flow update client.
// For Windows, we can't use conntrack, so we keep a map ourselves.
type Client struct {
	ignoreFlows map[string]bool
	mu          *sync.Mutex
}

// NewClient creates a new flow tracking client.
func NewClient(ctx context.Context) (*Client, error) {
	return &Client{
		ignoreFlows: make(map[string]bool),
		mu:          &sync.Mutex{},
	}, nil
}

// Close will close the connection of the client.
func (c *Client) Close() error {
	return nil
}

// ShouldIgnoreFlow checks map to see if we should tell Frontman to ignore flow.
func (c *Client) ShouldIgnoreFlow(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16) bool {
	key := fmt.Sprintf("%d %s %d %s %d", protonum, ipSrc, srcport, ipDst, dstport)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ignoreFlows[key]
}

// ClearIgnoreFlow deletes entry from map.
func (c *Client) ClearIgnoreFlow(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16) {
	key := fmt.Sprintf("%d %s %d %s %d", protonum, ipSrc, srcport, ipDst, dstport)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ignoreFlows, key)
}

// UpdateMark adds an entry to the map.
func (c *Client) UpdateMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32, network bool) error {
	if newmark == constants.DefaultConnMark {
		key := fmt.Sprintf("%d %s %d %s %d", protonum, ipSrc, srcport, ipDst, dstport)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.ignoreFlows[key] = true
	}
	return nil
}

func (c *Client) UpdateNetworkFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return c.UpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark, true)
}

func (c *Client) UpdateApplicationFlowMark(ipSrc, ipDst net.IP, protonum uint8, srcport, dstport uint16, newmark uint32) error {
	return c.UpdateMark(ipSrc, ipDst, protonum, srcport, dstport, newmark, false)
}

func (c *Client) GetOriginalDest(ipSrc, ipDst net.IP, srcport, dstport uint16, protonum uint8) (net.IP, uint16, uint32, error) {
	return nil, 0, 0, nil
}
