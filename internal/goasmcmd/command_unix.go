//go:build unix

package goasmcmd

import (
	"github.com/xgo-dev/plan9asm/internal/ownedprocess"
	"os/exec"
)

func run(command *exec.Cmd) error { return ownedprocess.Run(command) }

func configuredGroup(command *exec.Cmd) int {
	if command.Process != nil && command.SysProcAttr != nil && command.SysProcAttr.Setpgid {
		return command.Process.Pid
	}
	return 0
}
