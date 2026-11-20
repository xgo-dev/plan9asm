//go:build linux && amd64

package plan9asm

import (
	"os"
	"testing"
)

// Unlike emulated-host observation agreement, these required native roots
// retain the full independent ISA expectations, including PTEST's cleared AF.
// Missing tools, instructions or actual native backing are failures.
func TestCrossLinuxRuntimeMatrixX86DefinedStatusOriginalGoNumerical(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86DefinedStatusOriginalGoNumerical(t)
}

func TestCrossLinuxRuntimeMatrixX86DefinedStatusIndependentOriginalCNumerical(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86DefinedStatusIndependentOriginalCNumerical(t)
}

// The native kernel, original ABI0 executable and both translated ELF32
// executables are required. No Rosetta/QEMU or cross-object substitutes them.
func TestCrossLinuxRuntimeMatrixX86DefinedStatusNative386(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86DefinedStatusIA32RequireCapabilities(t)
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("required LLVM 22 llc missing")
	}
	t.Run("OriginalGo", func(t *testing.T) {
		original := x86DefinedStatusIA32BuildOriginal(t)
		output := x87IA32RunDirect(t, original, nil, os.Environ())
		if string(output) != "original defined-status observations 896 failures 0\n" {
			t.Fatalf("original Go IA32 ABI0 six-flag/LAHF/full canary oracle: %q", output)
		}
	})
	declarations, source := x86DefinedStatusIA32Fixture("386")
	ir := x86CPUQueryIRFromDeclaration(t, source, declarations, "386", "i386-unknown-linux-gnu", "Go")
	for _, level := range []string{"-O0", "-O2"} {
		t.Run(level, func(t *testing.T) {
			input := ir
			if level == "-O2" {
				input = x86UndefinedTrapOptimizedIR(t, input)
			}
			x86DefinedStatusIA32CompileAndRun(t, llc, input, level)
		})
	}
	x87IA32RequireNativeHost(t)
}
