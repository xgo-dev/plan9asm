package main

import (
	"os/exec"

	"github.com/xgo-dev/plan9asm/internal/ownedprocess"
)

func runOwnedCommand(cmd *exec.Cmd) error {
	return ownedprocess.Run(cmd)
}
