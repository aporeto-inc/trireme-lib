// +build windows

package nfqdatapath

import (
	"context"

	"github.com/pkg/errors"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/afinetrawsocket"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

func adjustConntrack(mode constants.ModeType) {
}

// ignoreFlow is for Windows, because we need a way to explicitly notify of an 'ignore flow' condition,
// without going through flowtracking, to be called synchronously in datapath processing
func (c *Datapath) ignoreFlow(pkt *packet.Packet, data interface{}) error {
	windata, _ := data.(*afinetrawsocket.WindowsPacketMetadata)
	if windata == nil {
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
