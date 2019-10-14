// +build darwin

package nflog

import (
	"context"

	"go.aporeto.io/trireme-lib/collector"
)

// nfLog TODO
type nfLog struct {
	getPUContext GetPUContextFunc // not called
}

// NewNFLogger provides an NFLog instance
func NewNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUContext GetPUContextFunc, collector collector.EventCollector) NFLogger {
	return &nfLog{getPUContext: getPUContext}
}

func (n *nfLog) Run(ctx context.Context) {}
