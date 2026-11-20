package goasmcmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestActualGoCommandBoundsAndMachineStdout(t *testing.T) {
	for _, mode := range []string{"json", "stderr", "exit", "stdout overflow", "stderr overflow", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if mode == "cancel" {
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
				defer cancel()
			}
			env := append(os.Environ(), "GOASM_COMMAND_FIXTURE="+mode)
			data, err := Run(ctx, t.TempDir(), env, os.Args[0], "-test.run=^TestActualGoCommandFixture$")
			if mode == "json" {
				if err != nil || string(data) != `{"actual":true}` {
					t.Fatalf("machine stdout changed: %q %v", data, err)
				}
				return
			}
			if err == nil || data != nil {
				t.Fatalf("command %s falsely succeeded: %q %v", mode, data, err)
			}
			if mode == "cancel" && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("cancellation lost deadline evidence: %v", err)
			}
			if mode == "stderr" && !strings.Contains(err.Error(), "download diagnostic") {
				t.Fatalf("stderr was swallowed: %v", err)
			}
			if strings.HasSuffix(mode, "overflow") && !strings.Contains(err.Error(), "output bound exceeded") {
				t.Fatalf("overflow was swallowed: %v", err)
			}
		})
	}
}

func TestActualObservationRetainsExitAndSeparateStreams(t *testing.T) {
	for _, mode := range []string{"json", "stderr", "exit", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			budget := 5 * time.Second
			if mode == "cancel" {
				budget = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(context.Background(), budget)
			defer cancel()
			value, err := Observe(ctx, t.TempDir(), append(os.Environ(), "GOASM_COMMAND_FIXTURE="+mode),
				os.Args[0], "-test.run=^TestActualGoCommandFixture$")
			encoded, _ := json.Marshal(value)
			t.Logf("ORACLE_CHILD %s", encoded)
			if !value.Waited || value.PID <= 1 {
				t.Fatalf("actual child not waited: %+v", value)
			}
			if mode == "cancel" {
				killedExit := -1
				if runtime.GOOS == "windows" {
					// os.Process.Kill uses TerminateProcess(handle, 1), not a
					// Unix signal. Preserve the exact observed exit and cause.
					killedExit = 1
				}
				if !errors.Is(err, context.DeadlineExceeded) || value.ExitCode != killedExit {
					t.Fatalf("deadline/killed exit lost: %+v %v", value, err)
				}
				return
			}
			if mode == "exit" {
				if err == nil || value.ExitCode != 7 {
					t.Fatalf("actual exit lost: %+v %v", value, err)
				}
				return
			}
			if err != nil || value.ExitCode != 0 || string(value.Stdout) != `{"actual":true}` {
				t.Fatalf("stdout changed: %+v %v", value, err)
			}
			if mode == "stderr" && string(value.Stderr) != "download diagnostic" {
				t.Fatalf("stderr not separate: %+v", value)
			}
		})
	}
}

func TestActualGoCommandFixture(t *testing.T) {
	switch os.Getenv("GOASM_COMMAND_FIXTURE") {
	case "json":
		_, _ = os.Stdout.WriteString(`{"actual":true}`)
	case "stderr":
		_, _ = os.Stdout.WriteString(`{"actual":true}`)
		_, _ = os.Stderr.WriteString("download diagnostic")
	case "stdout overflow":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), 4<<20+1))
	case "stderr overflow":
		_, _ = os.Stderr.Write(bytes.Repeat([]byte("x"), 4<<20+1))
	case "exit":
		os.Exit(7)
	case "signal":
		self, err := os.FindProcess(os.Getpid())
		if err != nil {
			os.Exit(2)
		}
		if err := self.Kill(); err != nil {
			os.Exit(2)
		}
	case "cancel":
		time.Sleep(time.Minute)
	default:
		return
	}
	os.Exit(0)
}

func TestActualObservationSignalAndMissingToolFail(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	observed, err := Observe(ctx, t.TempDir(), append(os.Environ(), "GOASM_COMMAND_FIXTURE=signal"),
		os.Args[0], "-test.run=^TestActualGoCommandFixture$")
	encoded, _ := json.Marshal(observed)
	t.Logf("ORACLE_CHILD %s", encoded)
	if err == nil || !observed.Waited || observed.PID <= 1 || observed.ExitCode == 0 {
		t.Fatalf("real killed child falsely succeeded: %+v %v", observed, err)
	}
	missing, err := Observe(ctx, t.TempDir(), nil, filepath.Join(t.TempDir(), "missing-go"))
	if err == nil || missing.Waited || missing.PID != 0 || missing.ExitCode != -1 {
		t.Fatalf("missing tool falsely succeeded: %+v %v", missing, err)
	}
}

func TestActualGoCommandRequiresLiveContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []context.Context{nil, ctx} {
		if _, err := Run(input, t.TempDir(), nil, "not-started"); err == nil {
			t.Fatal("inactive context started a command")
		}
	}
}

func TestObservationEarlyCancellationRetainsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	value, err := Observe(ctx, t.TempDir(), nil, "must-not-start")
	if !errors.Is(err, context.Canceled) || value.ExitCode != -1 || value.PID != 0 || value.Waited {
		t.Fatalf("early cancellation lost actual cause/no-child outcome: %+v %v", value, err)
	}
}
