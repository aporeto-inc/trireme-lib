// +build darwin

package nfqdatapath

import (
	"context"

	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
)

func adjustConntrack(mode constants.ModeType) {
}

func (d *Datapath) ignoreFlow(pkt *packet.Packet) error {
	return nil
}

func (d *Datapath) startInterceptors(ctx context.Context) {
}
