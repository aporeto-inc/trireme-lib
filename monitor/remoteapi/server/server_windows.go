// +build windows

package server

import (
	"net"
	"net/http"

	"go.aporeto.io/trireme-lib/v11/common"
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

// TODO(windows): Uids() not impl currently in Windows
func validateUser(r *http.Request, event *common.EventInfo) error {
	return nil
}
