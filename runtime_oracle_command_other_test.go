//go:build !unix

package plan9asm

import "os/exec"

// Non-Unix hosts retain the bounded pipe wait and original command failure.
// The process-group ownership assertion is exercised on Unix runtime lanes.
func runtimeOracleRun(command *exec.Cmd) error {
	return command.Run()
}
