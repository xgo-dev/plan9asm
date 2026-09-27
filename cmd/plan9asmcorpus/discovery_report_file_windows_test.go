package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDiscoveryWindowsFileErrorClassification(t *testing.T) {
	for _, test := range []struct {
		code syscall.Errno
		want bool
	}{
		{syscall.ERROR_ACCESS_DENIED, true},
		{syscall.ERROR_FILE_NOT_FOUND, true},
		{syscall.Errno(32), true},   // ERROR_SHARING_VIOLATION.
		{syscall.Errno(112), false}, // ERROR_DISK_FULL.
		{syscall.Errno(87), false},  // ERROR_INVALID_PARAMETER.
	} {
		err := &os.LinkError{Op: "rename", Old: "old", New: "new", Err: test.code}
		if got := transientDiscoveryFileError(fmt.Errorf("publish: %w", err)); got != test.want {
			t.Fatalf("error %v retryable=%t, want %t", err, got, test.want)
		}
	}
	if transientDiscoveryFileError(fmt.Errorf("not a Windows filesystem error")) {
		t.Fatal("retried unrelated error")
	}
}

func TestDiscoveryWindowsPublicationWaitsForExternalReader(t *testing.T) {
	file := filepath.Join(t.TempDir(), "shard-0.json")
	if err := writeDiscoveryCorpusReport(file, discoveryCorpusReport{Selected: 1}); err != nil {
		t.Fatal(err)
	}
	// Simulate an ordinary external reader without FILE_SHARE_DELETE. It does
	// not participate in the process-local publication mutex.
	reader, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan error, 1)
	go func() {
		time.Sleep(30 * time.Millisecond)
		closed <- reader.Close()
	}()
	err = writeDiscoveryCorpusReport(file, discoveryCorpusReport{Selected: 2})
	if closeErr := <-closed; closeErr != nil {
		t.Fatal(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	report, err := readDiscoveryCorpusReport(file)
	if err != nil || report.Selected != 2 {
		t.Fatalf("publication after reader closed: %+v %v", report, err)
	}
}
