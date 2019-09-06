// +build !linux

package dnsproxy

import (
	"go.aporeto.io/trireme-lib/collector"
	"go.aporeto.io/trireme-lib/controller/pkg/flowtracking"
	"go.aporeto.io/trireme-lib/utils/cache"
)

type Proxy struct {
}

// New creates an instance of the dns proxy
func New(puFromID cache.DataStore, conntrack flowtracking.FlowClient, c collector.EventCollector) *Proxy {
	return &Proxy{}
}

func (p *Proxy) ShutdownDNS(contextID string) {
}
