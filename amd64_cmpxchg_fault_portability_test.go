package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86CMPXCHGFaultWindowsHeaderBoundary(t *testing.T) {
	x86FaultWindowsHeaderBoundary(t, x86CMPXCHGFaultReference,
		[]string{"VirtualAlloc", "VirtualProtect", "VirtualFree", "kernel.original(p)", "kernel.translated(p)"})
}

func TestX86MemoryFaultWindowsHeaderBoundary(t *testing.T) {
	driver := x86MemoryFaultDriver("static int sample(const uint8_t *p) { return *p; }\n", "{sample, 4, 3},")
	x86FaultWindowsHeaderBoundary(t, driver,
		[]string{"VirtualAlloc", "VirtualProtect", "VirtualFree", "kernel.run(input)", "source[i]"})
}

func TestX86SignedConversionFaultWindowsHeaderBoundary(t *testing.T) {
	driver := x86MemoryFaultSupportC + `
static void sample(const void *p) { (void)p; }
static const struct { void (*run)(const void *); unsigned width, bits; }
    cases[] = {{sample, 4, 32}};
` + x86SignedIntegerFloatFaultMainC
	x86FaultWindowsHeaderBoundary(t, driver,
		[]string{"VirtualAlloc", "VirtualProtect", "VirtualFree", "cases[row].run(input)", "cvtsi2ssl", "cvtsi2sdq"})
}

func x86FaultWindowsHeaderBoundary(t *testing.T, driver string, required []string) {
	t.Helper()
	clang := findLLVM22Tool("clang")
	if clang == "" {
		t.Fatal("LLVM 22 clang required")
	}
	directory := t.TempDir()
	if err := os.Mkdir(filepath.Join(directory, "sys"), 0700); err != nil {
		t.Fatal(err)
	}
	// This observes actual preprocessing of the complete driver, not a
	// Windows SDK, object, link or runtime claim. Missing POSIX dependencies
	// are poisoned so the host cannot accidentally supply them.
	for _, name := range []string{"stdint.h", "stdio.h", "string.h", "stdlib.h", "signal.h", "windows.h"} {
		if err := os.WriteFile(filepath.Join(directory, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"unistd.h", "sys/mman.h", "sys/resource.h", "sys/wait.h"} {
		if err := os.WriteFile(filepath.Join(directory, filepath.FromSlash(name)), []byte("#error unexpected_POSIX_fault_dependency\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	input := filepath.Join(directory, "fault.c")
	if err := os.WriteFile(input, []byte(driver), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, clang, "-target", "x86_64-w64-windows-gnu", "-nostdinc",
		"-I", directory, "-E", "-P", input)
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if err != nil {
		t.Fatalf("Windows fault driver still consumes POSIX headers: %v\n%s", err, output)
	}
	for _, operation := range required {
		if !strings.Contains(string(output), operation) {
			t.Fatal("Windows fault driver lost its real guard or operation", operation)
		}
	}
}
