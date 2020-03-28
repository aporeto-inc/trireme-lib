// +build linux

package nfqdatapath

import (
	"context"
	"os"

	"go.aporeto.io/trireme-lib/buildflags"
	"go.aporeto.io/trireme-lib/controller/constants"
	"go.aporeto.io/trireme-lib/controller/pkg/packet"
	"go.uber.org/zap"
)

func writeProcFile(path, value string) error {
	// If the file doesn't exist, create it, or append to the file
	f, err := os.OpenFile(path, os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	if _, err := f.Write([]byte(value)); err != nil {
		// ignore error; Write error takes precedence
		f.Close() // nolint
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return nil
}

func adjustConntrack(mode constants.ModeType) {
	var err error

	if err = writeProcFile("/proc/1/root/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal", "0"); err != nil {
		zap.L().Error("failed to set /proc/1/root/proc/sys/net/netfilter/nf_conntrack_tcp_be_liberal=0: %s", zap.Error(err))
	}

	if mode == constants.LocalServer && !buildflags.IsLegacyKernel() {
		if err = writeProcFile("/proc/1/root/proc/sys/net/ipv4/ip_early_demux", "0"); err != nil {
			zap.L().Error("failed to set /proc/1/root/proc/sys/net/ipv4/ip_early_demux=0: %s", zap.Error(err))
		}
	}

}

// ignoreFlow is for Windows. use flowtracking interface for Linux.
func (d *Datapath) ignoreFlow(pkt *packet.Packet) error {
	return nil
}

func (d *Datapath) startInterceptors(ctx context.Context) {
	d.startApplicationInterceptor(ctx)
	d.startNetworkInterceptor(ctx)
}
