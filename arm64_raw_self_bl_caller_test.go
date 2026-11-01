package plan9asm

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func TestCrossLinuxRuntimeMatrixARM64SelfBLCallerDetectsCorruption(t *testing.T) {
	_, _, compiler, runner := arm64FPPairRuntimeTools(t)
	for _, tc := range []struct {
		name, mutation, diagnostic string
	}{
		{name: "healthy"},
		{name: "g", mutation: "eor x28,x28,#1", diagnostic: "fixed=1"},
		{name: "os18", mutation: "eor x18,x18,#1", diagnostic: "fixed=1"},
		{name: "numeric", mutation: "eor x8,x8,#1", diagnostic: "output=-?[1-9][0-9]*"},
		{name: "output_canary", mutation: "strb wzr,[x1,#9]", diagnostic: "output=-?[1-9][0-9]*"},
		{name: "input_canary", mutation: "ldrb w9,[x0,#8]\\neor w9,w9,#1\\nstrb w9,[x0,#8]", diagnostic: "input=-?[1-9][0-9]*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The independent native stub deliberately bypasses the translator
			// and its source proof. It establishes that this caller observes
			// callee corruption, rather than just accepting a consistent IR.
			stub := fmt.Sprintf(`
__asm__(
    ".text\n"
    ".p2align 2\n"
    ".globl " TERMINAL_SYMBOL "\n"
    TERMINAL_SYMBOL ":\n"
    "ldr x8,[x0]\n"
    "%s\n"
    "str x8,[x1]\n"
    "ret\n");
`, tc.mutation)
			dir := t.TempDir()
			source := filepath.Join(dir, "caller.c")
			path := filepath.Join(dir, "caller")
			if err := os.WriteFile(source, []byte(arm64RawSelfBLOracleC+stub), 0600); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			args := append(append([]string(nil), compiler[1:]...), source, "-O2", "-o", path)
			command := exec.CommandContext(ctx, compiler[0], args...)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("compile independent caller-corruption stub: %v\n%s", err, output)
			}
			args = append(append([]string(nil), runner...), path)
			command = exec.CommandContext(ctx, args[0], args[1:]...)
			command.Env = append(os.Environ(), "SELF_BL_SINK=0")
			output, err := command.CombinedOutput()
			if tc.mutation == "" {
				if err != nil {
					t.Fatalf("healthy independent callee: %v\n%s", err, output)
				}
				return
			}
			if err == nil || !regexp.MustCompile(tc.diagnostic).Match(output) {
				t.Fatalf("callee corruption was not observed: %v\n%s", err, output)
			}
		})
	}
}
