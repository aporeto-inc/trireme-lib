package systemdutil

import (
	"os"
	"os/exec"

	"go.aporeto.io/enforcerd/trireme-lib/common"
)

// execve does not exist in Windows, so we do the best we can.
func execve(c *CLIRequest, env []string) error {
	cmd := exec.Command(c.Executable, c.Parameters...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func getPUType() common.PUType {
	return common.WindowsProcessPU
}
