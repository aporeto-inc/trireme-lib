// +build windows

package nfqdatapath

import (
	"context"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.uber.org/zap"
)

func adjustConntrack(mode constants.ModeType) {
}

func (d *Datapath) startInterceptors(ctx context.Context) {
	err := d.startFrontmanPacketFilter(ctx, d.nflogger)
	if err != nil {
		zap.L().Fatal("Unable to initialize windows packet proxy", zap.Error(err))
	}
}
