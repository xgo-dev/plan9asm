//go:build !unix

package plan9asm

import (
	"errors"
	"os/exec"
)

// Non-Unix requires our direct-child Kill acknowledgement and abnormal exit;
// it makes no claim about descendants or a Unix signal identity.
func runtimeOracleSinkCanceledExit(err error, killedDirectChild bool) bool {
	var exit *exec.ExitError
	return killedDirectChild && errors.As(err, &exit) && exit.ExitCode() != 0
}
