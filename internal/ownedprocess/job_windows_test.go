package ownedprocess

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsOpenedThreadRetainsProcessIdentity(t *testing.T) {
	thread := windows.CurrentThread()
	pid := uint32(os.Getpid())
	if err := verifyWindowsThreadOwner(thread, pid); err != nil {
		t.Fatal(err)
	}
	for _, foreign := range []uint32{0, 1, pid + 1} {
		if err := verifyWindowsThreadOwner(thread, foreign); err == nil {
			t.Fatalf("foreign process %d borrowed the current thread", foreign)
		}
	}
	if err := verifyWindowsThreadOwner(0, pid); err == nil {
		t.Fatal("missing thread handle acquired ownership")
	}
}
