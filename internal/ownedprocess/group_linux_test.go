//go:build linux

package ownedprocess

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLinuxOwnedGroupWaitsForTerminationWithUnreapedZombie(t *testing.T) {
	const variable = "PLAN9ASM_LINUX_GROUP_FIXTURE"
	switch os.Getenv(variable) {
	case "zombie":
		os.Exit(0)
	case "leader":
		if err := os.WriteFile("ready", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			os.Exit(2)
		}
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); {
			if _, err := os.Stat("release"); err == nil {
				os.Exit(0)
			}
			time.Sleep(time.Millisecond)
		}
		os.Exit(3)
	}
	directory := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := func(role string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxOwnedGroupWaitsForTerminationWithUnreapedZombie$")
		cmd.Env = append(os.Environ(), variable+"="+role)
		cmd.Dir = directory
		return cmd
	}
	leader := command("leader")
	done := make(chan error, 1)
	go func() { done <- Run(leader) }()
	joined := false
	defer func() {
		cancel()
		if !joined {
			<-done
		}
	}()
	var pgid int
	for pgid == 0 && ctx.Err() == nil {
		data, _ := os.ReadFile(filepath.Join(directory, "ready"))
		pgid, _ = strconv.Atoi(string(data))
		if pgid == 0 {
			time.Sleep(time.Millisecond)
		}
	}
	if pgid <= 1 {
		t.Fatal("owned leader did not become ready", ctx.Err())
	}
	child := command("zombie")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pgid: pgid}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	for {
		members, err := observeProcessGroup(pgid)
		if err != nil {
			t.Fatal(err)
		}
		exited := false
		for _, member := range members {
			exited = exited || member.PID == child.Process.Pid && member.State == "Z"
		}
		if exited {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("owned child failed to reach its actual zombie state", ctx.Err())
		}
		time.Sleep(time.Millisecond)
	}
	if err := os.WriteFile(filepath.Join(directory, "release"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	err := <-done
	joined = true
	if err != nil || leader.ProcessState == nil {
		t.Fatal("waited leader and truly exited child were not joined", err)
	}
	if err := syscall.Kill(child.Process.Pid, 0); err != nil {
		t.Fatal("independent parent did not retain the zombie until Wait", err)
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	end := strings.LastIndex(string(data), ") ")
	if end < 0 || !strings.HasPrefix(string(data), strconv.Itoa(child.Process.Pid)+" (") ||
		!strings.HasPrefix(string(data[end+2:]), "Z ") {
		t.Fatalf("independent kernel record does not prove this child exited: %s", data)
	}
	t.Logf("kernel terminal child remains visible until its owning parent reaps: %s", data)
}
