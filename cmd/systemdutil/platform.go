// +build !windows

package systemdutil

import "syscall"

func execve(c *CLIRequest, env []string) error {
	return syscall.Exec(c.Executable, append([]string{c.Executable}, c.Parameters...), env)
}
