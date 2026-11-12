//go:build unix && !darwin && !linux

package ownedprocess

// Other kernels retain the original strict signal outcome. In particular,
// EPERM is not evidence that a group has exited.
var observeProcessGroup groupObserver
