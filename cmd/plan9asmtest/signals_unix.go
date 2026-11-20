//go:build unix

package main

import (
	"os"
	"syscall"
)

func cancellationSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}
