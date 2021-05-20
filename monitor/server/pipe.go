// +build !windows

package server

import (
	"net"
	"os"

	"go.uber.org/zap"
)

func cleanupPipe(address string) error {
	// Cleanup the leftover socket first.
	if _, err := os.Stat(address); err == nil {
		if err := os.Remove(address); err != nil {
			zap.L().Error("Cannot remove existing pipe", zap.String("address", address), zap.Error(err))
			return err
		}
	}
	return nil
}

func makePipe(address string) (net.Listener, error) {
	// Start a custom listener
	addr, _ := net.ResolveUnixAddr("unix", address)
	nl, err := net.ListenUnix("unix", addr)
	if err != nil {
		zap.L().Error("Unable to start the listener", zap.String("address", address), zap.Error(err))
		return nil, err
	}

	// make it owner,group rw only.
	// TODO: which group ID? or should it be owner root rw only ?
	if err := os.Chmod(addr.String(), 0600); err != nil {
		zap.L().Error("Cannot set permissions on the pipe", zap.String("address", address), zap.Error(err))
		return nil, err
	}

	return nl, nil
}
