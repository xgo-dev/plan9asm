//go:build !unix

package gotoolprofile

import "os/exec"

func runOwnedCommand(command *exec.Cmd) error { return command.Run() }
