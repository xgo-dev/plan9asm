//go:build !unix

package goasmcmd

import "os/exec"

func run(command *exec.Cmd) error { return command.Run() }

func configuredGroup(command *exec.Cmd) int { return 0 }
