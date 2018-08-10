// +build windows

package nfqdatapath

import (
	"context"

	"go.aporeto.io/trireme-lib/controller/internal/enforcer/nfqdatapath/windatapath"

	"go.uber.org/zap"
)

const (
	networkFilter = "inbound"
	appFilter     = "outbound"
)

// startNetworkInterceptor will the process that processes  packets from the network
// Still has one more copy than needed. Can be improved.
func (d *Datapath) startNetworkInterceptor(ctx context.Context) {
	if hdl, err := windatapath.Newwindatapath(); err != nil {
		zap.L().Fatal("Unable to start windatapath", zap.Error(err))
	} else {

		if _, err := hdl.WinDivertOpen(networkFilter, 0, 0, 0); err != nil {
			zap.L().Fatal("Failed to open windivert device", zap.Error(err))
		}
	}

}

// startApplicationInterceptor will create a interceptor that processes
// packets originated from a local application
func (d *Datapath) startApplicationInterceptor(ctx context.Context) {}
