// +build windows

package server

import (
	"net"

	"gopkg.in/natefinch/npipe.v2"
)

func cleanupPipe(address string) error {
	// TODO(windows): anything?
	return nil
}

func (e *EventServer) makePipe() (net.Listener, error) {
	pipeName := `\\.\pipe\` + e.socketPath
	pipeListener, err := npipe.Listen(pipeName)
	if err != nil {
		return nil, err
	}
	return pipeListener, nil
}
