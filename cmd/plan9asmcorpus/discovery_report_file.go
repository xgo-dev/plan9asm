//go:build !windows

package main

import "os"

func openDiscoveryReport(name string) (*os.File, error) {
	return os.Open(name)
}

func publishDiscoveryReport(oldName, newName string) error {
	return os.Rename(oldName, newName)
}
