package systemdutil

import "os/exec"

func execve(c *CLIRequest, env []string) error {
	// TODO(windows): emulate execve as much as possible
	cmd := exec.Command(c.Executable, c.Parameters...)
	cmd.Env = env
	return cmd.Start()
}
