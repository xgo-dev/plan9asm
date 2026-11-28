//go:build unix

package gotoolprofile

import (
	"os/exec"
	"syscall"
)

func runOwnedCommand(command *exec.Cmd) error {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		return syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	return command.Run()
}
