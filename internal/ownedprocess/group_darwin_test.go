//go:build darwin

package ownedprocess

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestDarwinOwnedZombieGroup(t *testing.T) {
	if os.Getenv("PLAN9ASM_ZOMBIE_FIXTURE") == "1" {
		os.Exit(0)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestDarwinOwnedZombieGroup$")
	command.Env = append(os.Environ(), "PLAN9ASM_ZOMBIE_FIXTURE=1")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	pid := command.Process.Pid
	deadline := time.Now().Add(3 * time.Second)
	for {
		members, err := observeProcessGroup(pid)
		if err != nil {
			t.Fatalf("observe exact owned zombie: %v", err)
		}
		if len(members) == 1 && members[0].PID == pid && members[0].State == "Z" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("owned child did not become a zombie: %v", members)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("actual Darwin zombie-only group did not reproduce EPERM: %v", err)
	}
	err := stopGroup(pid, false, syscall.Kill, func(pgid int) ([]groupMember, error) {
		return []groupMember{{PID: pid, PGID: pgid, State: "Z"}}, nil
	})
	if !errors.Is(err, syscall.EPERM) || errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("unwaited owned group permission error was suppressed: %v", err)
	}
}

// Hold a zombie in the fresh group after its leader has actually been waited.
// Its outside-group supervisor is this test, so the kernel cannot reap it
// before the post-Wait cleanup check. Every process and file is test-owned.
func TestDarwinReapedParentZombieDescendant(t *testing.T) {
	switch os.Getenv("PLAN9ASM_REAPED_GROUP_FIXTURE") {
	case "leader":
		if err := os.WriteFile("ready", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(5)
		}
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
			if _, err := os.Stat("release"); err == nil {
				os.Exit(0)
			}
			time.Sleep(5 * time.Millisecond)
		}
		os.Exit(6)
	case "zombie":
		os.Exit(0)
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	leader := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDarwinReapedParentZombieDescendant$")
	leader.Env = append(os.Environ(), "PLAN9ASM_REAPED_GROUP_FIXTURE=leader")
	leader.Dir = dir
	done := make(chan error, 1)
	go func() { done <- Run(leader) }()
	finished := false
	defer func() {
		cancel()
		if !finished {
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Error("owned leader cleanup did not complete")
			}
		}
	}()
	var pgid int
	for end := time.Now().Add(3 * time.Second); pgid == 0; {
		if data, err := os.ReadFile(filepath.Join(dir, "ready")); err == nil {
			pgid, _ = strconv.Atoi(string(data))
		}
		if time.Now().After(end) {
			t.Fatal("owned leader did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestDarwinReapedParentZombieDescendant$")
	child.Env = append(os.Environ(), "PLAN9ASM_REAPED_GROUP_FIXTURE=zombie")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pgid}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = child.Process.Kill()
		_ = child.Wait()
	}()
	for end := time.Now().Add(3 * time.Second); ; {
		members, err := observeProcessGroup(pgid)
		if err != nil {
			t.Fatalf("owned descendant snapshot: %v", err)
		}
		exited := false
		for _, member := range members {
			if member.PID == child.Process.Pid && member.State == "Z" {
				exited = true
			}
		}
		if exited {
			break
		}
		if time.Now().After(end) {
			t.Fatalf("descendant did not exit: %v", members)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		finished = true
		if leader.ProcessState == nil {
			t.Fatal("leader was not actually waited")
		}
		if signalErr := syscall.Kill(-pgid, syscall.SIGKILL); !errors.Is(signalErr, syscall.EPERM) {
			t.Fatalf("actual zombie-only Darwin group: %v", signalErr)
		}
		if err != nil {
			t.Fatalf("reaped parent with zombie-only descendants rejected: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("post-Wait cleanup did not finish")
	}
}
