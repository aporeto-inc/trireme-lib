// +build darwin !linux

package nflog

import (
	"context"

	"go.aporeto.io/trireme-lib/collector"
)

// nfLog TODO
type nfLog struct {
}

// NewNFLogger provides an NFLog instance
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUContext GetPUContextFunc, collector collector.EventCollector) NFLogger {
	return &nfLog{}
}

func (n *nfLog) Run(ctx context.Context) {}
