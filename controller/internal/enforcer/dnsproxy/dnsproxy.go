package dnsproxy

import (
	"context"
	"net"

	"go.aporeto.io/enforcerd/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/enforcerd/trireme-lib/policy"
)

// DNSProxy defines an interface that trireme uses for Dns Proxy
type DNSProxy interface {

	// StartDNSServer starts the dns server on the port provided for contextID
	StartDNSServer(ctx context.Context, contextID, port string) error

	// Enforce starts enforcing policies for the given policy.PUInfo.
	Enforce(ctx context.Context, contextID string, puInfo *policy.PUInfo) error

	// Unenforce stops enforcing policy for the given IP.
	Unenforce(ctx context.Context, contextID string) error

	// SyncWithPlatformCache is only needed in Windows
	SyncWithPlatformCache(ctx context.Context, pctx *pucontext.PUContext) error

	// HandleDNSResponsePacket is only needed in Windows
	HandleDNSResponsePacket(dnsPacketData []byte, sourceIP net.IP, sourcePort uint16, destIP net.IP, destPort uint16, puFromContextID func(string) (*pucontext.PUContext, error)) error
}
