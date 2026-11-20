//go:build unix

package gotoolprofile

import (
	"os/exec"

	"github.com/xgo-dev/plan9asm/internal/ownedprocess"
)

func runOwnedCommand(command *exec.Cmd) error {
	return ownedprocess.Run(command)
}
