package packetprocessor

import (
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/controller/internal/enforcer/utils/tokens"
)

// PacketProcessor is an interface for extending packet processing functions such
// as encryption, deep packet inspection, etc. These functions are run inline during packet
// processing. A services processor must implement this interface.
type PacketProcessor interface {
	// Initialize  initializes the secrets of the processor
	Initialize(s secrets.Secrets, fq *fqconfig.FilterQueue)

	// Stop stops the packet processor
	Stop() error

	// PreProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PreProcessTCPAppPacket(p *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) bool

	// PostProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PostProcessTCPAppPacket(p *packet.Packet, action interface{}, context *pucontext.PUContext, conn *connection.TCPConnection) bool

	// PreProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PreProcessTCPNetPacket(p *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) bool

	// PostProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PostProcessTCPNetPacket(p *packet.Packet, action interface{}, claims *tokens.ConnectionClaims, context *pucontext.PUContext, conn *connection.TCPConnection) bool
}
