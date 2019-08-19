package packetprocessor

import (
	"go.aporeto.io/trireme-lib/controller/pkg/aclprovider"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/fqconfig"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
)

// PacketProcessor is an interface for extending packet processing functions such
// as encryption, deep packet inspection, etc. These functions are run inline during packet
// processing. A services processor must implement this interface.
type PacketProcessor interface {
	// Initialize  initializes any ACLs that the processor requires
	Initialize(fq *fqconfig.FilterQueue, p provider.IptablesProvider)

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

	// PreProcessUDPAppPacket will be called for application packets and return value of false means drop packet
	PreProcessUDPAppPacket(p *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection, packetType uint8) bool

	// PostProcessUDPAppPacket will be called for application packets and return value of false means drop packet.
	PostProcessUDPAppPacket(p *packet.Packet, action interface{}, context *pucontext.PUContext, conn *connection.UDPConnection) bool

	// PreProcessUDPNetPacket will be called for network packets and return value of false means drop packet
	PreProcessUDPNetPacket(p *packet.Packet, context *pucontext.PUContext, conn *connection.UDPConnection) bool

	// PostProcessUDPNetPacket will be called for network packets and return value of false means drop packet
	PostProcessUDPNetPacket(p *packet.Packet, action interface{}, claims *tokens.ConnectionClaims, context *pucontext.PUContext, conn *connection.UDPConnection) bool
}
