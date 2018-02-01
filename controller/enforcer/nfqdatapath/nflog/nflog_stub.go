// +build darwin !linux

package nflog

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/collector"
)

// nfLog TODO
type nfLog struct {
}

// NewNFLogger provides an NFLog instance
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUInfo GetPUInfoFunc, collector collector.EventCollector) NFLogger {
	return &nfLog{}
}

func (n *nfLog) Run(ctx context.Context) {}
