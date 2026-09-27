package main

import (
	"sync"
	"time"
)

// Keep local readers out of the replacement window. Other processes can still
// hold Windows handles, so publication also has bounded OS-specific retries.
var discoveryReportMu sync.RWMutex

func retryDiscoveryFileOperation(operation func() error, transient func(error) bool, now func() time.Time, sleep func(time.Duration)) error {
	deadline := now().Add(2 * time.Second)
	delay := time.Millisecond
	for {
		err := operation()
		if err == nil || !transient(err) {
			return err
		}
		remaining := deadline.Sub(now())
		if remaining <= 0 {
			return err
		}
		if delay > remaining {
			delay = remaining
		}
		sleep(delay)
		if !now().Before(deadline) {
			return err
		}
		if delay < 50*time.Millisecond {
			delay *= 2
		}
	}
}
