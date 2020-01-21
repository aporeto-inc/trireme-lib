// +build windows

package client

import (
	"context"
	"net"

	"gopkg.in/natefinch/npipe.v2"
)

// Client is an api client structure.
type Client struct {
	pipeName string
}

// NewClient creates a new client.
func NewClient(path string) (*Client, error) {
	return &Client{pipeName: `\\.\pipe\` + path}, nil
}

func (c *Client) getDialContext() dialContextFunc {
	return func(_ context.Context, _, _ string) (net.Conn, error) {
		return npipe.Dial(c.pipeName)
	}
}
