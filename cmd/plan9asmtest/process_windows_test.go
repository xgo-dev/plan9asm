//go:build windows

package main

import (
	"bytes"
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

	"golang.org/x/sys/windows"
)

// Use real descendants, including one retaining the parent's output pipe.
// Neither taskkill by image name nor killing just the immediate child suffices.
func TestWindowsOwnedCommandTree(t *testing.T) {
	for _, role := range []string{"exit", "failure", "cancel"} {
		t.Run(role, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			cmd := windowsOwnershipHelper(ctx, "parent", dir, role)
			var output bytes.Buffer
			cmd.Stdout, cmd.Stderr = &output, &output
			cmd.WaitDelay = time.Second
			done := make(chan error, 1)
			go func() { done <- runOwnedCommand(cmd) }()
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
					t.Error("owned command failed to finish cleanup")
				}
			})

			var handles []windows.Handle
			for _, name := range []string{"parent", "child", "grandchild"} {
				pid := waitWindowsOwnedPID(t, filepath.Join(dir, name), done)
				handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_TERMINATE, false, pid)
				if err != nil {
					t.Fatal(err)
				}
				handles = append(handles, handle)
				t.Cleanup(func() {
					// Also clean a faulty implementation's actual fixture process.
					windows.TerminateProcess(handle, 1)
					windows.CloseHandle(handle)
				})
			}
			if role == "cancel" {
				cancel()
			} else if err := os.WriteFile(filepath.Join(dir, "release"), nil, 0600); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				done <- err // Cleanup observes completion too.
				if role == "exit" && err != nil {
					t.Fatalf("ordinary parent exit must close inherited pipes: %v\n%s", err, output.String())
				}
				if role != "exit" && err == nil {
					t.Fatal("failed/cancelled command became successful")
				}
				if role == "failure" {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 7 {
						t.Fatalf("original exit status lost: %v", err)
					}
				}
			case <-time.After(10 * time.Second):
				t.Fatal("owned command blocked on a descendant or its pipe")
			}
			for i, handle := range handles {
				state, err := windows.WaitForSingleObject(handle, 0)
				if err != nil || state != windows.WAIT_OBJECT_0 {
					t.Errorf("process %d still live after Run returned: state=%d error=%v", i, state, err)
				}
			}
		})
	}
}

func TestWindowsOwnedCommandDoesNotKillPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := t.TempDir()
	peer := windowsOwnershipHelper(ctx, "grandchild", dir, "")
	if err := peer.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		peer.Process.Kill()
		peer.Wait()
	})
	cmd := windowsOwnershipHelper(ctx, "immediate", t.TempDir(), "")
	if err := runOwnedCommand(cmd); err != nil {
		t.Fatal(err)
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(peer.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(handle)
	if state, err := windows.WaitForSingleObject(handle, 0); err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("unowned peer was killed: state=%d error=%v", state, err)
	}
}

func TestWindowsOwnedCommandStartFailures(t *testing.T) {
	plain := exec.Command(os.Args[0], "-test.run=^TestWindowsOwnedCommandHelper$", "--", "immediate", t.TempDir(), "")
	if err := runOwnedCommand(plain); err != nil {
		t.Fatalf("ordinary non-context command failed: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := windowsOwnershipHelper(ctx, "immediate", t.TempDir(), "")
	if err := runOwnedCommand(cmd); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-start cancellation lost: %v", err)
	}
	if err := runOwnedCommand(exec.Command(filepath.Join(t.TempDir(), "missing.exe"))); err == nil {
		t.Fatal("missing executable was successful")
	}
}

func windowsOwnershipHelper(ctx context.Context, role, dir, result string) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsOwnedCommandHelper$", "--", role, dir, result)
}

func waitWindowsOwnedPID(t *testing.T, path string, done chan error) uint32 {
	t.Helper()
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 32); err == nil && pid > 1 {
				return uint32(pid)
			}
		}
		select {
		case err := <-done:
			done <- err
			t.Fatalf("command ended before descendant readiness: %v", err)
		case <-deadline.C:
			t.Fatal("descendant readiness timed out")
		case <-ticker.C:
		}
	}
}

func TestWindowsOwnedCommandHelper(t *testing.T) {
	if len(os.Args) != 6 || os.Args[2] != "--" {
		return
	}
	role, dir, result := os.Args[3], os.Args[4], os.Args[5]
	if role == "immediate" {
		os.Exit(0)
	}
	if err := os.WriteFile(filepath.Join(dir, role), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if role == "parent" || role == "child" {
		next := "child"
		if role == "child" {
			next = "grandchild"
		}
		child := windowsOwnershipHelper(context.Background(), next, dir, result)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for {
		if role == "parent" {
			if _, err := os.Stat(filepath.Join(dir, "release")); err == nil {
				fmt.Println("parent completed")
				if result == "failure" {
					os.Exit(7)
				}
				os.Exit(0)
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}
