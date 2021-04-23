// +build linux

package k8smonitor

import (
	"syscall"
)

// syscallKill points to syscall.Kill and can be overwritten in unit tests
var syscallKill func(pid int, sig syscall.Signal) (err error) = syscall.Kill

func sandboxIsRunning(pid int) (bool, error) {
	if err := syscallKill(pid, syscall.Signal(0)); err != nil {
		// the expected error is ESRCH: The process or process group does not exist.
		if err != syscall.ESRCH {
			return false, err
		}

		// this is a successful check that the process is dead
		// and therefore the sandbox is not running anymore
		return false, nil
	}

	// otherwise it means that the process is not dead and is still running
	return true, nil
}
