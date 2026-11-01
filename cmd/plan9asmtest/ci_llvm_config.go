package main

import (
	"os"
	"os/exec"
)

// Selection only: captureCIScope still observes and verifies the actual version
// and bindir. An explicit configuration is authoritative and never falls back.
func resolveCIConfigExecutable() (string, error) {
	requested := os.Getenv("LLVM_CONFIG")
	if requested == "" {
		requested = "llvm-config"
		if versioned, err := exec.LookPath("llvm-config-22"); err == nil {
			requested = versioned
		}
	}
	return exec.LookPath(requested)
}
