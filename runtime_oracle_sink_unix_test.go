//go:build unix

package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/ownedprocess"
)

func runtimeOracleSinkCanceledExit(err error, killedDirectChild bool) bool {
	var exit *exec.ExitError
	if !killedDirectChild || errors.Is(err, ownedprocess.ErrCleanup) || !errors.As(err, &exit) {
		return false
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	return ok && status.Signaled() && status.Signal() == syscall.SIGKILL
}

func TestRuntimeOracleSinkCanceledExitRequiresKillWitness(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeOracleSinkKilledFixture$")
	command.Env = append(os.Environ(), "PLAN9ASM_RUNTIME_KILLED_SINK=self-kill", "GORACE=atexit_sleep_ms=0")
	err := runtimeOracleRun(command)
	if ctx.Err() != nil || !runtimeOracleSinkCanceledExit(err, true) {
		t.Fatalf("fixture did not produce its independent SIGKILL: %v", err)
	}
	if runtimeOracleSinkCanceledExit(err, false) {
		t.Fatal("SIGKILL without this observer's kill witness was accepted")
	}
	if runtimeOracleSinkCanceledExit(errors.Join(err, ownedprocess.ErrCleanup), true) {
		t.Fatal("descendant cleanup failure was accepted")
	}
}

func TestRuntimeOracleSinkRejectsPreviouslyKilledParent(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "owned-pipe-holder.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	factory := func(ctx context.Context) *exec.Cmd {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeOracleSinkKilledFixture$")
		command.Env = append(os.Environ(),
			"PLAN9ASM_RUNTIME_KILLED_SINK=parent",
			"PLAN9ASM_RUNTIME_KILLED_SINK_PID="+pidFile,
			"GORACE=atexit_sleep_ms=0",
		)
		return command
	}
	output, observeErr := runtimeOracleObserveSink(ctx, factory, time.Second, 300*time.Millisecond)
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("fixture did not publish its owned descendant: %v; observer=%v output=%q", err, observeErr, output)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 1 {
		t.Fatalf("invalid owned descendant identity %q: %v", data, err)
	}
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	// The private identity belongs only to this fixture, including a RED.
	defer child.Kill()
	runtimeOracleAssertChildStopped(t, pid)
	t.Logf("previously killed parent: observer=%v output=%q", observeErr, output)
	if observeErr == nil || string(output) != "entered\n" {
		t.Fatalf("previous SIGKILL was accepted as observer cancellation: %v output=%q", observeErr, output)
	}
	if !errors.Is(observeErr, os.ErrProcessDone) {
		t.Fatalf("previous exit was not rejected by the direct-child witness: %v", observeErr)
	}
}

func TestRuntimeOracleSinkKilledFixture(t *testing.T) {
	mode := os.Getenv("PLAN9ASM_RUNTIME_KILLED_SINK")
	if mode == "" {
		return
	}
	if mode == "self-kill" {
		if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
			t.Fatal(err)
		}
		os.Exit(24)
	}
	pidFile := os.Getenv("PLAN9ASM_RUNTIME_KILLED_SINK_PID")
	if pidFile == "" {
		t.Fatal("killed sink requires its private descendant identity")
	}
	if mode == "holder" {
		if err := os.WriteFile(pidFile+".ready", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(pidFile+".ready", pidFile); err != nil {
			t.Fatal(err)
		}
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	if mode != "parent" {
		t.Fatalf("unknown killed sink fixture %q", mode)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRuntimeOracleSinkKilledFixture$")
	child.Env = append(os.Environ(), "PLAN9ASM_RUNTIME_KILLED_SINK=holder")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	deadline := time.Now().Add(time.Second)
	for {
		if _, err := os.Stat(pidFile); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if !time.Now().Before(deadline) {
			t.Fatal("pipe holder did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	fmt.Println("entered")
	// The parent dies independently; its descendant keeps the output pipe
	// open, so Cmd.Wait has not returned when the observation window ends.
	if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	os.Exit(24)
}
