// +build linux

package nfqdatapath

import (
	"context"
	"os/exec"

	"go.aporeto.io/trireme-lib/buildflags"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.uber.org/zap"
)

func adjustConntrack(mode constants.ModeType) {
	sysctlCmd, err := exec.LookPath("sysctl")
	if err != nil {
		zap.L().Fatal("sysctl command must be installed", zap.Error(err))
	}

	cmd := exec.Command(sysctlCmd, "-w", "net.netfilter.nf_conntrack_tcp_be_liberal=1")
	if err := cmd.Run(); err != nil {
		zap.L().Fatal("Failed to set conntrack options", zap.Error(err))
	}

	if mode == constants.LocalServer && !buildflags.IsLegacyKernel() {
		cmd = exec.Command(sysctlCmd, "-w", "net.ipv4.ip_early_demux=0")
		if err := cmd.Run(); err != nil {
			zap.L().Fatal("Failed to set early demux options", zap.Error(err))
		}
	}
}

func (d *Datapath) startInterceptors(ctx context.Context) {
	d.startApplicationInterceptor(ctx)
	d.startNetworkInterceptor(ctx)
}
