// +build !windows

package systemdutil

import (
	"syscall"

	"go.aporeto.io/enforcerd/trireme-lib/common"
)

func execve(c *CLIRequest, env []string) error {
	return syscall.Exec(c.Executable, append([]string{c.Executable}, c.Parameters...), env)
}

func getPUType() common.PUType {
	return common.LinuxProcessPU
}
