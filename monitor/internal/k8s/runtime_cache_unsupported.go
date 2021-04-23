// +build !linux,!windows

package k8smonitor

import (
	"errors"
)

func sandboxIsRunning(pid int) (bool, error) {
	return false, errors.New("unsupported platform")
}
