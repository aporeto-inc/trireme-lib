package packetprocessor

import (
	"github.com/aporeto-inc/trireme-lib/enforcer/connection"
	"github.com/aporeto-inc/trireme-lib/enforcer/pucontext"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/fqconfig"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/packet"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/secrets"
	"github.com/aporeto-inc/trireme-lib/enforcer/utils/tokens"
)

// PacketProcessor is an interface implemented to stitch into our enforcer
type PacketProcessor interface {
	// Initialize  initializes the secrets of the processor
	Initialize(s secrets.Secrets, fq *fqconfig.FilterQueue)

	// PreProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PreProcessTCPAppPacket(p *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) bool

	// PostProcessTCPAppPacket will be called for application packets and return value of false means drop packet.
	PostProcessTCPAppPacket(p *packet.Packet, action interface{}, context *pucontext.PUContext, conn *connection.TCPConnection) bool

	// PreProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PreProcessTCPNetPacket(p *packet.Packet, context *pucontext.PUContext, conn *connection.TCPConnection) bool

	// PostProcessTCPNetPacket will be called for network packets and return value of false means drop packet
	PostProcessTCPNetPacket(p *packet.Packet, action interface{}, claims *tokens.ConnectionClaims, context *pucontext.PUContext, conn *connection.TCPConnection) bool
}
