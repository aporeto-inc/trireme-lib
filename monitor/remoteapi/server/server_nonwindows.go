// +build !windows

package server

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/process"
	"go.aporeto.io/trireme-lib/v11/common"
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

// validateUser validates that the originating user is not sending a request
// for a process that they don't own. Root users are allowed to send
// any event.
func validateUser(r *http.Request, event *common.EventInfo) error {

	// Find the calling user.
	parts := strings.Split(r.RemoteAddr, ":")
	if len(parts) != 3 {
		return fmt.Errorf("Invalid user context")
	}

	// Accept all requests from root users
	if parts[0] == "0" {
		return nil
	}

	// The target process must be valid.
	p, err := process.NewProcess(event.PID)
	if err != nil {
		return fmt.Errorf("Process not found")
	}

	// The UID of the calling process must match the UID of the target process.
	uids, err := p.Uids()
	if err != nil {
		return fmt.Errorf("Unknown user ID")
	}

	match := false
	for _, uid := range uids {
		if strconv.Itoa(int(uid)) == parts[0] {
			match = true
		}
	}

	if !match {
		return fmt.Errorf("Invalid user - no access to this process: %+v PARTS: %+v", event, parts)
	}

	return nil
}
