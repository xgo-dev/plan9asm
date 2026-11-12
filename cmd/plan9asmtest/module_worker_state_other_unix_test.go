//go:build unix && !linux

package main

func moduleWorkerKernelTerminal(int) (string, bool) {
	return "process absence was not established", false
}
