// +build darwin !linux

package enforcer

import "github.com/aporeto-inc/trireme/collector"

// nfLog TODO
type nfLog struct {
}

func newNFLogger(ipv4groupSource, ipv4groupDest uint16, getPUInfo puInfoFunc, collector collector.EventCollector) nfLogger {
	return nil
}

func (n *nfLog) start() {}
