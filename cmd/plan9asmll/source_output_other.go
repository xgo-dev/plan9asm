//go:build !unix

package main

import "path/filepath"

func sameOutputFilesystem(stage, destination string) error {
	// Both names were resolved through the opened physical-path observer;
	// junctions cannot hide a different Windows destination volume here.
	if filepath.VolumeName(stage) != filepath.VolumeName(destination) {
		return compileOutputError()
	}
	return nil
}
