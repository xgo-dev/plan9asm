package main

import (
	"fmt"
	"strings"
)

// Windows' externally configured LLVM binding also needs its tag in nested
// Go commands. Preserve that one inherited setting only when the invocation
// explicitly declares the identical selection. Reports retain the declared
// flags, and module scopes retain the unchanged actual GOFLAGS observation.
func validateRunnerGoFlags(goos, inherited string, flags []string) error {
	if inherited == "" {
		return nil
	}
	if goos != "windows" || inherited != "-tags=byollvm" {
		return fmt.Errorf("GOFLAGS must be empty except for explicitly declared Windows -tags=byollvm")
	}
	forwarded, _, err := validateFlags(flags)
	if err != nil {
		return err
	}
	tags := 0
	for i := 0; i < len(forwarded); i++ {
		name, value, inline := strings.Cut(forwarded[i], "=")
		if !inline && !runnerBooleanFlag(strings.TrimPrefix(name, "-")) {
			i++ // validateFlags already checked the value exists.
			value = forwarded[i]
		}
		if name != "-tags" {
			continue
		}
		tags++
		if tags != 1 || value != "byollvm" {
			return fmt.Errorf("explicit build tags conflict with inherited GOFLAGS=-tags=byollvm")
		}
	}
	if tags != 1 {
		return fmt.Errorf("inherited GOFLAGS=-tags=byollvm requires explicit -tags=byollvm")
	}
	return nil
}
