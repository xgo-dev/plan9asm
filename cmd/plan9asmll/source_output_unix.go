//go:build unix

package main

import (
	"os"
	"syscall"
)

func sameOutputFilesystem(stage, destination string) error {
	left, err := os.Stat(stage)
	if err != nil {
		return err
	}
	right, err := os.Stat(destination)
	if err != nil {
		return err
	}
	leftStat, leftOK := left.Sys().(*syscall.Stat_t)
	rightStat, rightOK := right.Sys().(*syscall.Stat_t)
	if !leftOK || !rightOK || leftStat.Dev != rightStat.Dev {
		return compileOutputError()
	}
	return nil
}
