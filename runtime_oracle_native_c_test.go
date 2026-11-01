package plan9asm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/nativeoracle"
)

// Only native-host C drivers use this helper. Cross-target object compilation
// retains its independent target/sysroot contract. Callers still select LLVM
// 22 and own the actual compiler/driver commands through the bounded runner.
func runtimeOracleNativeCCommand(t *testing.T, ctx context.Context, clang string, arguments ...string) *exec.Cmd {
	t.Helper()
	if runtime.GOOS == "darwin" {
		flags, err := nativeoracle.DarwinClangFlags(ctx, os.Environ())
		if err != nil {
			t.Fatal(err)
		}
		arguments = append(flags, arguments...)
	}
	return exec.CommandContext(ctx, clang, arguments...)
}

func TestRuntimeOracleNativeCActualHeadersAndLink(t *testing.T) {
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang required")
	}
	directory := t.TempDir()
	input := filepath.Join(directory, "native.c")
	executable := filepath.Join(directory, "native")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	const source = `#include <stdint.h>
#include <stdio.h>
int main(void) {
    uint64_t value = UINT64_C(123456789);
    return printf("%llu", (unsigned long long)value) != 9;
}
`
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			command := runtimeOracleNativeCCommand(t, ctx, clang, level, input, "-o", executable)
			x86FloatCompareCaptureCommand(t, command)
			output := x86FloatCompareCaptureCommand(t, exec.Command(executable))
			if string(output) != "123456789" {
				t.Fatalf("actual host C headers/link/runtime changed: %q", output)
			}
		})
	}
}
