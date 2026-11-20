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
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/ownedprocess"
)

func runtimeOracleRun(command *exec.Cmd) error {
	return ownedprocess.Run(command)
}

func TestRuntimeOracleCommandFixture(t *testing.T) {
	mode := os.Getenv("PLAN9ASM_RUNTIME_COMMAND_FIXTURE")
	if mode == "" {
		return
	}
	pidFile := os.Getenv("PLAN9ASM_RUNTIME_COMMAND_CHILD_PID")
	if pidFile == "" {
		t.Fatal("runtime command fixture requires its owned child identity")
	}
	if mode == "child" {
		fmt.Println("owned child holds its parent's output pipe")
		if err := os.WriteFile(pidFile+".ready", []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(pidFile+".ready", pidFile); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	if mode != "parent" && mode != "parent-exit" {
		t.Fatalf("unknown runtime command fixture %q", mode)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestRuntimeOracleCommandFixture$")
	child.Env = append(os.Environ(), "PLAN9ASM_RUNTIME_COMMAND_FIXTURE=child")
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer child.Process.Kill()
	if mode == "parent-exit" {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := os.Stat(pidFile); err == nil {
				os.Exit(23)
			} else if !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if time.Now().After(deadline) {
				t.Fatal("child did not publish its ready identity")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	time.Sleep(30 * time.Second)
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeOracleCommandCancelsOwnedDescendant(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "owned-child.pid")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeOracleCommandFixture$")
	command.Env = append(os.Environ(),
		"PLAN9ASM_RUNTIME_COMMAND_FIXTURE=parent",
		"PLAN9ASM_RUNTIME_COMMAND_CHILD_PID="+pidFile,
	)
	type result struct {
		output []byte
		err    error
	}
	done := make(chan result, 1)
	go func() {
		output, err := runtimeOracleCombinedOutput(ctx, command)
		done <- result{output: output, err: err}
	}()

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	pid := 0
	for pid == 0 {
		select {
		case <-ticker.C:
			data, err := os.ReadFile(pidFile)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				cancel()
				t.Fatal(err)
			}
			pid, err = strconv.Atoi(string(data))
			if err != nil || pid <= 1 {
				cancel()
				t.Fatalf("invalid owned child identity %q: %v", data, err)
			}
		case result := <-done:
			t.Fatalf("fixture exited before its child was ready: %v\n%s", result.err, result.output)
		case <-deadline.C:
			cancel()
			t.Fatal("owned child did not reach its bounded readiness witness")
		}
	}
	// This exact PID came from this invocation's private readiness file. The
	// cleanup also makes the unfixed RED safe: never signal the test's group.
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Kill()
	cancel()
	select {
	case result := <-done:
		if !errors.Is(result.err, context.Canceled) {
			t.Fatalf("cancellation lost its error: %v\n%s", result.err, result.output)
		}
		if !strings.Contains(string(result.output), "owned child holds") {
			t.Fatalf("runtime child output was discarded: %q", result.output)
		}
	case <-time.After(3 * time.Second):
		// Unblock the legacy CombinedOutput before reporting its actual RED.
		_ = child.Kill()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("parent did not return even after exact-owned child cleanup")
		}
		t.Fatal("canceled runtime command left its child holding the output pipe")
	}
	runtimeOracleAssertChildStopped(t, pid)
}

func TestRuntimeOracleCommandCleansDescendantAfterParentExit(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "owned-child.pid")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeOracleCommandFixture$")
	command.Env = append(os.Environ(),
		"PLAN9ASM_RUNTIME_COMMAND_FIXTURE=parent-exit",
		"PLAN9ASM_RUNTIME_COMMAND_CHILD_PID="+pidFile,
	)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	data, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("parent exit lost its owned child identity: %v", readErr)
	}
	pid, parseErr := strconv.Atoi(string(data))
	if parseErr != nil || pid <= 1 {
		t.Fatalf("invalid owned child identity %q: %v", data, parseErr)
	}
	child, findErr := os.FindProcess(pid)
	if findErr != nil {
		t.Fatal(findErr)
	}
	defer child.Kill()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("parent exit was lost or cleanup exceeded its bound: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "owned child holds") {
		t.Fatalf("parent exit lost its child's output: %q", output)
	}
	runtimeOracleAssertChildStopped(t, pid)
}

func runtimeOracleAssertChildStopped(t *testing.T, pid int) {
	t.Helper()
	checkCtx, checkCancel := context.WithTimeout(context.Background(), time.Second)
	defer checkCancel()
	state, err := exec.CommandContext(checkCtx, "/bin/ps", "-p", strconv.Itoa(pid), "-o", "stat=").CombinedOutput()
	if checkCtx.Err() != nil {
		t.Fatal(checkCtx.Err())
	}
	if strings.TrimSpace(string(state)) == "" {
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("unknown owned child observation: %v %q", err, state)
		}
	} else if err != nil || len(strings.Fields(string(state))) != 1 || strings.TrimSpace(string(state))[0] != 'Z' {
		t.Fatalf("owned child is still live or has unknown state: %v %q", err, state)
	}
}
