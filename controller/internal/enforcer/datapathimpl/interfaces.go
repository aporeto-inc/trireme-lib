package datapathimpl

import (
	"context"

	"github.com/aporeto-inc/trireme-lib/controller/pkg/packet"
)

type DataPathPacketHandler interface {
	ProcessNetworkPacket(p *packet.Packet) error
	ProcessApplicationPacket(p *packet.Packet) error
}

type DatapathImpl interface {
	StartNetworkInterceptor(ctx context.Context)
	StartApplicationInterceptor(ctx context.Context)
}
