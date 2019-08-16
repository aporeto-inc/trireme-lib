// +build !windows

package server

import (
	"fmt"
	"net"
	"os"
)

func cleanupPipe(address string) error {
	// Cleanup the socket first.
	if _, err := os.Stat(address); err == nil {
		if err := os.Remove(address); err != nil {
			return fmt.Errorf("Cannot create clean up socket: %s", err)
		}
	}
	return nil
}

func (e *EventServer) makePipe() (net.Listener, error) {
	// Start a custom listener
	addr, _ := net.ResolveUnixAddr("unix", e.socketPath)
	nl, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("Unable to start API server: %s", err)
	}

	// We make the socket accesible to all users of the system.
	// TODO: create a trireme group for this
	if err := os.Chmod(addr.String(), 0766); err != nil {
		return nil, fmt.Errorf("Cannot make the socket accessible to all users: %s", err)
	}

	return &UIDListener{nl}, nil
}
