// +build !windows

package client

import (
	"context"
	"fmt"
	"net"
)

// Client is an api client structure.
type Client struct {
	addr *net.UnixAddr
}

// NewClient creates a new client.
func NewClient(path string) (*Client, error) {
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %s", err)
	}

	return &Client{addr: addr}, nil
}

func (c *Client) getDialContext() dialContextFunc {
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		return net.DialUnix("unix", nil, c.addr)
	}
}
