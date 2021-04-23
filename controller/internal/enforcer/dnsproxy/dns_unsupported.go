// +build !linux,!windows

package dnsproxy

import (
	"context"
	"net"

	"go.aporeto.io/enforcerd/trireme-lib/collector"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/flowtracking"
	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
	"go.aporeto.io/enforcerd/trireme-lib/utils/cache"
)

// Proxy struct represents the object for dns proxy
type Proxy struct {
}

// New creates an instance of the dns proxy
func New(ctx context.Context, puFromID cache.DataStore, conntrack flowtracking.FlowClient, c collector.EventCollector) *Proxy {
	return &Proxy{}
}

// ShutdownDNS shuts down the dns server for contextID
func (p *Proxy) ShutdownDNS(contextID string) {

}

// StartDNSServer starts the dns server on the port provided for contextID
func (p *Proxy) StartDNSServer(ctx context.Context, contextID, port string) error {
	return nil
}

// SyncWithPlatformCache is only needed in Windows currently
func (p *Proxy) SyncWithPlatformCache(ctx context.Context, pctx *pucontext.PUContext) error {
	return nil
}

// HandleDNSResponsePacket is only needed in Windows currently
func (p *Proxy) HandleDNSResponsePacket(dnsPacketData []byte, sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16, puFromContextID func(string) (*pucontext.PUContext, error)) error {
	return nil
}

// Enforce starts enforcing policies for the given policy.PUInfo.
func (p *Proxy) Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error {
	return nil
}

// Unenforce stops enforcing policy for the given IP.
func (p *Proxy) Unenforce(_ context.Context, contextID string) error {
	return nil
}
