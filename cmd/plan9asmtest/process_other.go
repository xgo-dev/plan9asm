//go:build !unix && !windows

package main

import (
	"fmt"
	"os/exec"
)

func runOwnedCommand(cmd *exec.Cmd) error {
	return fmt.Errorf("exhaustive runner requires Unix owned-process-group cleanup; this host is not yet supported")
}
