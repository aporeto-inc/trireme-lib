package datapathimpl

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
)

// DataPathPacketHandler is the interface used by the datapath to pass packets to the higher layers
type DataPathPacketHandler interface {
	ProcessNetworkPacket(p *packet.Packet) error
	ProcessApplicationPacket(p *packet.Packet) error
}

// DatapathImpl is the interface called from the the enforcer to start the infra to receive packets
type DatapathImpl interface {
	CleanUp() error
	StartNetworkInterceptor(ctx context.Context) error
	StartApplicationInterceptor(ctx context.Context) error
}
