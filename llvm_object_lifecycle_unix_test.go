//go:build unix

package plan9asm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLLVMObjectHelperDeadlineFixture(t *testing.T) {
	mode := os.Getenv("PLAN9ASM_OBJECT_HELPER_FIXTURE")
	if mode == "" {
		return
	}
	// The helper's five-second test deadline leaves two seconds before its
	// cleanup reserve. Do not spend that window starting two more copies of
	// the large LLVM-linked test binary just to hold an output pipe.
	// This failure-only shim creates one real pipe-holding child; it never
	// emits an object or impersonates successful Go/LLVM output.
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal("deadline fixture requires sleep:", err)
	}
	t.Setenv("PLAN9ASM_OBJECT_HELPER_SLEEP", sleep)
	shim := filepath.Join(t.TempDir(), "go")
	const script = `#!/bin/sh
"$PLAN9ASM_OBJECT_HELPER_SLEEP" 30 &
child=$!
printf '%s' "$child" > "$PLAN9ASM_RUNTIME_COMMAND_CHILD_PID" || exit 1
printf '%s\n' "owned child holds its parent's output pipe"
wait "$child"
`
	if err := os.WriteFile(shim, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "object":
		compileLLVMToObject(t, shim, arm64LinuxGNUTriple, "deadline.ll", "deadline.o", "define void @deadline() { ret void }\n")
	case "go-env":
		t.Setenv("PATH", filepath.Dir(shim))
		output, err := testGoEnv(t, "GOROOT")
		if err != nil {
			t.Fatalf("go env failed: %v\n%s", err, output)
		}
	default:
		t.Fatalf("unknown object helper fixture %q", mode)
	}
	t.Fatal("failure-only helper unexpectedly succeeded")
}

func TestLLVMObjectHelperDeadlineCleansOwnedDescendant(t *testing.T) {
	for _, mode := range []string{"object", "go-env"} {
		t.Run(mode, func(t *testing.T) {
			pidFile := filepath.Join(t.TempDir(), "owned-child.pid")
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0],
				"-test.run=^TestLLVMObjectHelperDeadlineFixture$", "-test.timeout=5s", "-test.v")
			command.Env = append(os.Environ(),
				"PLAN9ASM_OBJECT_HELPER_FIXTURE="+mode,
				"PLAN9ASM_RUNTIME_COMMAND_CHILD_PID="+pidFile,
			)
			output, err := runtimeOracleCombinedOutput(ctx, command)
			data, readErr := os.ReadFile(pidFile)
			if readErr != nil {
				t.Fatalf("owned descendant did not publish its identity: %v\n%s", readErr, output)
			}
			pid, parseErr := strconv.Atoi(string(data))
			if parseErr != nil || pid <= 1 {
				t.Fatalf("invalid owned descendant identity %q: %v", data, parseErr)
			}
			child, findErr := os.FindProcess(pid)
			if findErr != nil {
				t.Fatal(findErr)
			}
			defer child.Kill()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("helper did not fail within its own stage deadline: %v\n%s", err, output)
			}
			for _, witness := range []string{"context deadline exceeded", "owned child holds its parent's output pipe"} {
				if !strings.Contains(string(output), witness) {
					t.Fatalf("helper discarded deadline/output witness %q: %v\n%s", witness, err, output)
				}
			}
			runtimeOracleAssertChildStopped(t, pid)
		})
	}
}
