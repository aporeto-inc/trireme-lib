// +build windows

package nfqdatapath

import (
	"context"

	"github.com/pkg/errors"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/connection"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	tpacket "go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.aporeto.io/trireme-lib/controller/pkg/pucontext"
	"go.aporeto.io/trireme-lib/controller/pkg/tokens"
	"go.aporeto.io/trireme-lib/policy"
	"go.uber.org/zap"
)

func adjustConntrack(mode constants.ModeType) {
}

// ignoreFlow is for Windows, because we need a way to explicitly notify of an 'ignore flow' condition,
// without going through flowtracking, to be called synchronously in datapath processing
func (d *Datapath) ignoreFlow(pkt *packet.Packet) error {
	windata, ok := pkt.PlatformMetadata.(*afinetrawsocket.PacketMetadata)
	if !ok {
		return errors.New("no WindowsPacketMetadata for ignoreFlow")
	}
	windata.IgnoreFlow = true
	return nil
}

func (d *Datapath) startInterceptors(ctx context.Context) {
	err := d.startFrontmanPacketFilter(ctx, d.nflogger)
	if err != nil {
		zap.L().Fatal("Unable to initialize windows packet proxy", zap.Error(err))
	}
}

// TODO(windows): implement this and other stuff that is currently in diagnostics_tcp.go
func (d *Datapath) initiateDiagnostics(_ context.Context, contextID string, pingConfig *policy.PingConfig) error {
	return nil
}

func (d *Datapath) processDiagnosticNetSynPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	claims *tokens.ConnectionClaims,
) error {
	return nil
}

func (d *Datapath) processDiagnosticNetSynAckPacket(
	context *pucontext.PUContext,
	tcpConn *connection.TCPConnection,
	tcpPacket *tpacket.Packet,
	claims *tokens.ConnectionClaims,
	ext bool,
	custom bool,
) error {
	return nil
}
