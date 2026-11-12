//go:build darwin

package ownedprocess

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDarwinMembershipIncludesNoTTYLiveMembers(t *testing.T) {
	if os.Getenv("PLAN9ASM_NO_TTY_FIXTURE") == "1" {
		if err := os.WriteFile("ready", nil, 0600); err != nil {
			os.Exit(5)
		}
		time.Sleep(10 * time.Second)
		os.Exit(0)
	}
	dir := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestDarwinMembershipIncludesNoTTYLiveMembers$")
	child.Dir = dir
	child.Env = append(os.Environ(), "PLAN9ASM_NO_TTY_FIXTURE=1")
	// A new session has no controlling terminal. It must not disappear
	// from the kernel group selector, even when its creator is in another one.
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	for end := time.Now().Add(3 * time.Second); ; {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		if time.Now().After(end) {
			t.Fatal("no-TTY child did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	pgid, err := syscall.Getpgid(child.Process.Pid)
	if err != nil || pgid != child.Process.Pid {
		t.Fatalf("test-owned independent group: %d %v", pgid, err)
	}
	members, err := observeProcessGroup(pgid)
	if err != nil || len(members) != 1 || members[0].PID != child.Process.Pid || members[0].State[0] == 'Z' {
		t.Fatalf("no-TTY live group member was hidden: %v %v", members, err)
	}
	permission := stopGroup(pgid, true, func(int, syscall.Signal) error { return syscall.EPERM }, observeProcessGroup)
	if !errors.Is(permission, syscall.EPERM) || errors.Is(permission, os.ErrProcessDone) {
		t.Fatalf("actual live no-TTY group suppressed a permission error: %v", permission)
	}
}
